//! XFTP v3/v4 smoke против живого XFTP-релея: HTTP/2 POST поверх TLS 1.3
//! (ALPN "xftp/1"), handshake, PING, FNEW -> SIDS, FPUT, FGET (recipient),
//! дешифровка внешнего слоя (crypto_box DH + cbNonce) и внутреннего (secretbox),
//! проверка digest, FDEL.
//!
//! Запуск:
//!   cargo run --release --bin xftp_smoke -- xftp1.simplex.im 443 [expectedKeyHashB64url]
//!
//! NOTE: публичный релей без SNI отдаёт XFTP-сертификат; со SNI — web (ERR SESSION).
//! Поэтому SNI не шлём, идентификатор релея сверяем по keyHash = SHA-256(CA DER).

use bytes::Bytes;
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use sha2::Digest;
use tokio::net::TcpStream;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use nexxrust::crypto;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

const BLOCK: usize = 16384;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn spki_ed25519(vk: &VerifyingKey) -> Vec<u8> {
    let mut v = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    v.extend_from_slice(&vk.to_bytes());
    v
}

fn spki_x25519(pk: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00];
    v.extend_from_slice(pk);
    v
}

/// raw NaCl secretbox (без hsalsa20 pre-layer, как sbInit/cbInit в XFTP):
/// crate возвращает `tag || ct`.
fn sb_encrypt(key: &[u8; 32], nonce: &[u8; 24], msg: &[u8]) -> Vec<u8> {
    use crypto_secretbox::aead::{Aead, KeyInit};
    use crypto_secretbox::XSalsa20Poly1305;
    XSalsa20Poly1305::new(key.into())
        .encrypt(nonce.into(), crypto_secretbox::aead::Payload::from(msg))
        .expect("sb encrypt")
}

fn sb_decrypt(key: &[u8; 32], nonce: &[u8; 24], tag_ct: &[u8]) -> Result<Vec<u8>, String> {
    use crypto_secretbox::aead::{Aead, KeyInit};
    use crypto_secretbox::XSalsa20Poly1305;
    XSalsa20Poly1305::new(key.into())
        .decrypt(nonce.into(), crypto_secretbox::aead::Payload::from(tag_ct))
        .map_err(|e| format!("sb decrypt: {e}"))
}

/// Потоковый формат XFTP (cb/sb stream): ciphertext || tail-tag(16B) —
/// приводим к порядку crate `tag || ct`.
fn sb_decrypt_tail_tag(key: &[u8; 32], nonce: &[u8; 24], body: &[u8]) -> Result<Vec<u8>, String> {
    if body.len() < 16 {
        return Err("body too short".into());
    }
    let (ct, tag) = body.split_at(body.len() - 16);
    let mut tag_ct = tag.to_vec();
    tag_ct.extend_from_slice(ct);
    sb_decrypt(key, nonce, &tag_ct)
}

fn block(payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.extend_from_slice(payload);
    b.resize(BLOCK, 0x23);
    b
}

/// transmission = short(sid) + short(corr) + short(entity) + cmd
fn transmission(sid: &[u8], corr: &[u8], entity: &[u8], cmd: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.push(sid.len() as u8);
    t.extend_from_slice(sid);
    t.push(corr.len() as u8);
    t.extend_from_slice(corr);
    t.push(entity.len() as u8);
    t.extend_from_slice(entity);
    t.extend_from_slice(cmd);
    t
}

/// batch = 0x01 + u16 len + auth + transmission ; auth = 0x00 | shortString(sig)
fn batch_block(auth: &[u8], t: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(auth);
    inner.extend_from_slice(t);
    let mut b = vec![1u8];
    b.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    b.extend_from_slice(&inner);
    block(&b)
}

fn corr() -> Vec<u8> {
    crypto::random_bytes(24)
}

fn show_resp(r: &[u8]) -> String {
    if r.len() < 2 {
        return format!("{}B", r.len());
    }
    let l = u16::from_be_bytes([r[0], r[1]]) as usize;
    String::from_utf8_lossy(&r[2..(2 + l).min(r.len())]).to_string()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let host = args.first().cloned().unwrap_or_else(|| "xftp1.simplex.im".into());
    let port: u16 = args.get(1).cloned().unwrap_or_else(|| "443".into()).parse().unwrap();
    let expected_kh = args.get(2).cloned();
    println!("=== NeXX XFTP smoke: {host}:{port} ===");

    // ---- TLS: без SNI (со SNI публичный релей отдаёт web), ALPN xftp/1 ----
    let mut builder = SslConnector::builder(SslMethod::tls()).expect("connector");
    builder.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    builder
        .set_sigalgs_list("ed448:ed25519:ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512")
        .unwrap();
    builder.set_groups_list("X25519").unwrap();
    builder.set_alpn_protos(b"\x06xftp/1").unwrap();
    builder.set_verify(openssl::ssl::SslVerifyMode::NONE); // пиннинг по keyHash ниже
    let connector = builder.build();
    let tcp = TcpStream::connect((host.as_str(), port)).await.expect("tcp");
    // Ssl без hostname => SNI не шлём
    let mut ssl_obj = openssl::ssl::Ssl::new(connector.context()).expect("ssl");
    ssl_obj.set_alpn_protos(b"\x06xftp/1").unwrap();
    let mut ssl = tokio_openssl::SslStream::new(ssl_obj, tcp).expect("stream");
    {
        let mut pinned = std::pin::Pin::new(&mut ssl);
        pinned.as_mut().connect().await.expect("tls handshake");
    }
    println!("OK  TLS {} ALPN={:?}", ssl.ssl().version_str(), ssl.ssl().selected_alpn_protocol());

    // sessionId = client TLS Finished (v7.1+: tls-unique)
    let mut fin_buf = [0u8; 64];
    let fin_len = ssl.ssl().finished(&mut fin_buf);
    let session_id = fin_buf[..fin_len].to_vec();
    println!("OK  sessionId (Finished, {}B) = {}", session_id.len(), hex(&session_id[..8]));

    // keyHash = SHA-256(CA DER, последний в цепочке)
    let chain = ssl.ssl().peer_cert_chain().expect("peer chain");
    let ca_der = chain.iter().last().expect("ca").to_der().expect("der");
    let key_hash: [u8; 32] = sha2::Sha256::digest(&ca_der).into();
    println!("OK  keyHash = {}", crypto::base64url_encode(&key_hash));
    if let Some(exp) = &expected_kh {
        let exp_raw = crypto::base64url_decode(exp).unwrap_or_default();
        if exp_raw != key_hash {
            println!("FAIL keyHash mismatch: expected {exp}");
            std::process::exit(1);
        }
        println!("OK  keyHash совпадает с ожидаемым из адреса");
    }

    let (mut h2, conn) = h2::client::handshake(ssl).await.expect("h2 handshake");
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("h2 conn error: {e}");
        }
    });

    async fn post(h2: &mut h2::client::SendRequest<Bytes>, body: Bytes, authority: &str) -> Bytes {
        let req = http::Request::builder()
            .method("POST")
            .uri(format!("https://{authority}/"))
            .body(())
            .unwrap();
        let (resp, mut stream) = h2.send_request(req, false).expect("send");
        stream.send_data(body, true).expect("send_data");
        let resp = tokio::time::timeout(std::time::Duration::from_secs(30), resp)
            .await
            .expect("resp timeout")
            .expect("resp");
        let status = resp.status();
        let mut rbody = resp.into_body();
        let mut data = Vec::new();
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(20), rbody.data()).await {
                Ok(Some(chunk)) => {
                    let chunk = chunk.expect("chunk");
                    let n = chunk.len();
                    data.extend_from_slice(&chunk);
                    let _ = rbody.flow_control().release_capacity(n);
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        println!("  POST {}B -> HTTP {status}, {}B body", data.len(), data.len());
        Bytes::from(data)
    }

    // ---- 1. empty POST -> serverHello ----
    let sh = post(&mut h2, Bytes::new(), &host).await;
    if sh.len() < 8 {
        println!("FAIL serverHello too short ({}B)", sh.len());
        std::process::exit(1);
    }
    let pl = u16::from_be_bytes([sh[0], sh[1]]) as usize;
    let p = &sh[2..(2 + pl).min(sh.len())];
    let vmin = u16::from_be_bytes([p[0], p[1]]);
    let vmax = u16::from_be_bytes([p[2], p[3]]);
    let sidl = p[4] as usize;
    let srv_sid = &p[5..(5 + sidl).min(p.len())];
    println!("OK  serverHello: vRange {vmin}..{vmax} sessionId={}B", srv_sid.len());
    if srv_sid != session_id.as_slice() {
        println!("WARN server sessionId != our Finished ({}B vs {}B)", srv_sid.len(), session_id.len());
    }
    let v = vmax.min(4).max(vmin.min(4));
    println!("OK  negotiated xftp v{v}");

    // ---- 2. clientHello -> empty response ----
    let mut ch = Vec::new();
    ch.extend_from_slice(&v.to_be_bytes());
    ch.push(32u8);
    ch.extend_from_slice(&key_hash);
    if v >= 4 {
        ch.push(b'0'); // entitlementProof = Nothing
    }
    let chr = post(&mut h2, Bytes::from(block(&ch)), &host).await;
    if !chr.is_empty() {
        println!("FAIL clientHello rejected: {}", show_resp(&chr));
        std::process::exit(1);
    }
    println!("OK  clientHello v{v} accepted");

    // ---- 3. PING ----
    let c = corr();
    let t = transmission(&session_id, &c, b"", b"PING");
    let pr = post(&mut h2, Bytes::from(batch_block(&[0u8], &t)), &host).await;
    println!("OK  PING -> {}", show_resp(&pr));
    if !pr.windows(4).any(|w| w == b"PONG") {
        println!("FAIL no PONG");
        std::process::exit(1);
    }

    // ---- 4. FNEW ----
    let snd = SigningKey::from_bytes(&crypto::random_bytes(32).try_into().unwrap());
    let rcv = SigningKey::from_bytes(&crypto::random_bytes(32).try_into().unwrap());
    // packet size 64KB: bodyPart (шифротекст) должен быть ровно size байт,
    // поэтому plaintext = 65536 - 16 (tag secretbox)
    let file: Vec<u8> = (0..(64 * 1024 - 16) as u32).map(|i| (i % 251) as u8).collect();
    let file_key: [u8; 32] = crypto::random_bytes(32).try_into().unwrap();
    let file_nonce: [u8; 24] = crypto::random_bytes(24).try_into().unwrap();
    let enc_file = sb_encrypt(&file_key, &file_nonce, &file); // tag||ct
    let digest: [u8; 32] = sha2::Sha256::digest(&enc_file).into(); // сервер сверяет SHA-256 тела (receiveFile_)
    let mut cmd = b"FNEW ".to_vec();
    let snd_spki = spki_ed25519(&snd.verifying_key());
    cmd.push(snd_spki.len() as u8);
    cmd.extend_from_slice(&snd_spki);
    cmd.extend_from_slice(&(enc_file.len() as u32).to_be_bytes()); // size = размер bodyPart (64KB packet)
    cmd.push(32u8);
    cmd.extend_from_slice(&digest);
    let rcv_spki = spki_ed25519(&rcv.verifying_key());
    cmd.push(1u8);
    cmd.push(rcv_spki.len() as u8);
    cmd.extend_from_slice(&rcv_spki);
    cmd.push(b'0'); // basicAuth = Nothing
    cmd.push(b'0'); // storageHours = Nothing (v>=4)
    let c = corr();
    let t = transmission(&session_id, &c, b"", &cmd);
    let sig = snd.sign(&t);
    let mut auth = vec![64u8];
    auth.extend_from_slice(&sig.to_bytes());
    let fr = post(&mut h2, Bytes::from(batch_block(&auth, &t)), &host).await;
    let fs = show_resp(&fr);
    println!("    FNEW -> {}", String::from_utf8_lossy(&fs.as_bytes()[..fs.len().min(100)]));
    let pl = u16::from_be_bytes([fr[0], fr[1]]) as usize;
    let fp = &fr[2..(2 + pl).min(fr.len())];
    let tail = &fp[fp.len().saturating_sub(24)..];
    println!("    FNEW resp tail: {:02x?} | {}", tail, String::from_utf8_lossy(tail));
    let pos = match fp.windows(4).position(|w| w == b"SIDS") {
        Some(p) => p,
        None => {
            println!("FAIL no SIDS in FNEW response");
            std::process::exit(1);
        }
    };
    let mut p = pos + 5;
    let sidl2 = fp[p] as usize;
    p += 1;
    let sender_id = fp[p..p + sidl2].to_vec();
    p += sidl2;
    let nrcv = fp[p] as usize;
    p += 1;
    let ridl = fp[p] as usize;
    p += 1;
    let rcv_id = fp[p..p + ridl].to_vec();
    println!("OK  FNEW -> SIDS senderId({}B) nRcv={nrcv} rcvId({}B)", sender_id.len(), rcv_id.len());

    // ---- 5. FPUT: entity=senderId, body = block + enc_file ----
    let c = corr();
    let t = transmission(&session_id, &c, &sender_id, b"FPUT");
    let sig = snd.sign(&t);
    let mut auth = vec![64u8];
    auth.extend_from_slice(&sig.to_bytes());
    let mut blk = batch_block(&auth, &t);
    blk.extend_from_slice(&enc_file);
    let pr = post(&mut h2, Bytes::from(blk), &host).await;
    let ps = show_resp(&pr);
    println!("OK  FPUT -> {ps}");
    if !pr.windows(2).any(|w| w == b"OK") {
        println!("FAIL FPUT");
        std::process::exit(1);
    }

    // ---- 6. FGET (recipient): entity=rcvId, cmd FGET + rDhKey, подписано rcv ----
    let r_dh = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let r_dh_pub = X25519Public::from(&r_dh);
    let rdh_spki = spki_x25519(r_dh_pub.as_bytes());
    let mut cmd = b"FGET ".to_vec();
    cmd.push(rdh_spki.len() as u8);
    cmd.extend_from_slice(&rdh_spki);
    let c = corr();
    let t = transmission(&session_id, &c, &rcv_id, &cmd);
    let sig = rcv.sign(&t);
    let mut auth = vec![64u8];
    auth.extend_from_slice(&sig.to_bytes());
    let gr = post(&mut h2, Bytes::from(batch_block(&auth, &t)), &host).await;
    if gr.len() < BLOCK + 16 {
        println!("FAIL FGET short response ({}B): {}", gr.len(), show_resp(&gr));
        std::process::exit(1);
    }
    let pl = u16::from_be_bytes([gr[0], gr[1]]) as usize;
    let head = &gr[2..(2 + pl).min(gr.len())];
    let pos = match head.windows(4).rposition(|w| w == b"FILE") {
        Some(p) => p,
        None => {
            println!("FAIL no FILE: {}", String::from_utf8_lossy(&head[..head.len().min(80)]));
            std::process::exit(1);
        }
    };
    let mut p = pos + 5;
    let sl = head[p] as usize;
    p += 1;
    let sdh_spki = &head[p..p + sl];
    p += sl;
    let cb_nonce: [u8; 24] = head[p..p + 24].try_into().unwrap();
    println!("    sDhKey spki len={sl} cbNonce={}", hex(&cb_nonce[..8]));
    // sDhKey из SPKI: последние 32 байта
    let s_dh_pub = X25519Public::from(<[u8; 32]>::try_from(&sdh_spki[sdh_spki.len() - 32..]).unwrap());
    let dh_secret = r_dh.diffie_hellman(&s_dh_pub);
    let enc_body = &gr[BLOCK..]; // тело после 16384-блока
    println!("OK  FGET -> FILE sDhKey cbNonce, body {}B", enc_body.len());
    let body = {
        let k = nexxrust::protocols::smp::crypto_box_beforenm(dh_secret.as_bytes());
        match sb_decrypt_tail_tag(&k, &cb_nonce, enc_body) {
            Ok(b) => b,
            Err(_) => match sb_decrypt(&k, &cb_nonce, enc_body) {
                Ok(b) => b,
                Err(_) => sb_decrypt_tail_tag(dh_secret.as_bytes(), &cb_nonce, enc_body)
                    .expect("outer cb decrypt (raw key, tail tag)"),
            },
        }
    };
    println!("OK  outer layer decrypted: {}B", body.len());
    // внутренняя: tag||ct (crate порядок)
    let plain = sb_decrypt(&file_key, &file_nonce, &body).expect("inner sb decrypt");
    if plain != file {
        println!("FAIL inner content mismatch ({} vs {}B)", plain.len(), file.len());
        std::process::exit(1);
    }
    println!("OK  file roundtrip matches ({}B)", plain.len());

    // ---- 7. FDEL (sender) ----
    let c = corr();
    let t = transmission(&session_id, &c, &sender_id, b"FDEL");
    let sig = snd.sign(&t);
    let mut auth = vec![64u8];
    auth.extend_from_slice(&sig.to_bytes());
    let dr = post(&mut h2, Bytes::from(batch_block(&auth, &t)), &host).await;
    let ds = show_resp(&dr);
    println!("OK  FDEL -> {ds}");
    if !dr.windows(2).any(|w| w == b"OK") {
        println!("FAIL FDEL");
        std::process::exit(1);
    }
    println!("=== XFTP INTEROP OK ===");
}
