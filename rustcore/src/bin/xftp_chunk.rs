//! XFTP chunked upload >64KB против живого XFTP-релея (Этап 3.1 плана эволюции).
//!
//! По спецификации simplexmq XFTP: один "data packet" — фиксированный размер
//! (64KB/256KB/1MB/4MB). Большой файл режется на chunk'и, каждый chunk —
//! отдельный FNEW/FPUT (своими snd/rcv ключами), скачивание — FGET на каждый
//! chunk, сборка по file description (per-chunk digest + SHA512 всего файла).
//!
//! Здесь: файл 256KB → 4 chunk'а по 65520 байт plaintext (64KB packet = 65536
//! bodyPart = ct + 16B tag). Внутренний слой: один fileKey на весь файл,
//! nonce chunk'а = fileNonce с последними 8 байтами = big-endian индекс chunk'а
//! (детерминированно, не нужно хранить per-chunk nonce в дескрипторе).
//!
//! Запуск:
//!   cargo run --release --bin xftp_chunk -- xftp1.simplex.im 443

use bytes::Bytes;
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use sha2::Digest;
use tokio::net::TcpStream;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use nexxrust::crypto;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

const BLOCK: usize = 16384;
/// plaintext на chunk: 64KB packet = 65536 bodyPart, из них 16B tag secretbox.
const CHUNK_PLAIN: usize = 64 * 1024 - 16;
/// тестовый файл: 4 chunk'а = 256KB
fn test_file() -> Vec<u8> {
    (0..4 * CHUNK_PLAIN as u32).map(|i| (i % 251) as u8).collect()
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

/// потоковый формат XFTP: ciphertext || tail-tag(16B) → порядок crate tag || ct.
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

/// nonce chunk'а: fileNonce, младшие 8 байт = big-endian index chunk'а.
fn chunk_nonce(file_nonce: &[u8; 24], index: usize) -> [u8; 24] {
    let mut n = *file_nonce;
    n[16..24].copy_from_slice(&(index as u64).to_be_bytes());
    n
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let host = args.first().cloned().unwrap_or_else(|| "xftp1.simplex.im".into());
    let port: u16 = args.get(1).cloned().unwrap_or_else(|| "443".into()).parse().unwrap();
    println!("=== NeXX XFTP chunked (>64KB): {host}:{port} ===");

    let mut builder = SslConnector::builder(SslMethod::tls()).expect("connector");
    builder.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    builder
        .set_sigalgs_list("ed448:ed25519:ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512")
        .unwrap();
    builder.set_groups_list("X25519").unwrap();
    builder.set_alpn_protos(b"\x06xftp/1").unwrap();
    builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let connector = builder.build();
    let tcp = TcpStream::connect((host.as_str(), port)).await.expect("tcp");
    let mut ssl_obj = openssl::ssl::Ssl::new(connector.context()).expect("ssl");
    ssl_obj.set_alpn_protos(b"\x06xftp/1").unwrap();
    let mut ssl = tokio_openssl::SslStream::new(ssl_obj, tcp).expect("stream");
    {
        let mut pinned = std::pin::Pin::new(&mut ssl);
        pinned.as_mut().connect().await.expect("tls handshake");
    }
    println!("OK  TLS {} ALPN={:?}", ssl.ssl().version_str(), ssl.ssl().selected_alpn_protocol());

    let mut fin_buf = [0u8; 64];
    let fin_len = ssl.ssl().finished(&mut fin_buf);
    let session_id = fin_buf[..fin_len].to_vec();

    let chain = ssl.ssl().peer_cert_chain().expect("peer chain");
    let ca_der = chain.iter().last().expect("ca").to_der().expect("der");
    let key_hash: [u8; 32] = sha2::Sha256::digest(&ca_der).into();
    println!("OK  keyHash = {}", crypto::base64url_encode(&key_hash));

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
        let resp = tokio::time::timeout(std::time::Duration::from_secs(60), resp)
            .await
            .expect("resp timeout")
            .expect("resp");
        let status = resp.status();
        let mut rbody = resp.into_body();
        let mut data = Vec::new();
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(30), rbody.data()).await {
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
        println!("  POST -> HTTP {status}, {}B body", data.len());
        Bytes::from(data)
    }

    // serverHello / clientHello / PING — как в xftp_smoke
    let sh = post(&mut h2, Bytes::new(), &host).await;
    let pl = u16::from_be_bytes([sh[0], sh[1]]) as usize;
    let p = &sh[2..(2 + pl).min(sh.len())];
    let vmin = u16::from_be_bytes([p[0], p[1]]);
    let vmax = u16::from_be_bytes([p[2], p[3]]);
    let v = vmax.min(4).max(vmin.min(4));
    println!("OK  negotiated xftp v{v}");
    let mut ch = Vec::new();
    ch.extend_from_slice(&v.to_be_bytes());
    ch.push(32u8);
    ch.extend_from_slice(&key_hash);
    if v >= 4 {
        ch.push(b'0');
    }
    let chr = post(&mut h2, Bytes::from(block(&ch)), &host).await;
    if !chr.is_empty() {
        println!("FAIL clientHello rejected: {}", show_resp(&chr));
        std::process::exit(1);
    }
    let c = corr();
    let t = transmission(&session_id, &c, b"", b"PING");
    let pr = post(&mut h2, Bytes::from(batch_block(&[0u8], &t)), &host).await;
    if !pr.windows(4).any(|w| w == b"PONG") {
        println!("FAIL no PONG");
        std::process::exit(1);
    }
    println!("OK  PING -> PONG");

    // ---- chunked upload ----
    let file = test_file();
    let file_key: [u8; 32] = crypto::random_bytes(32).try_into().unwrap();
    let file_nonce: [u8; 24] = crypto::random_bytes(24).try_into().unwrap();
    let file_sha512 = sha2::Sha512::digest(&file);
    let n_chunks = file.len().div_ceil(CHUNK_PLAIN);
    println!("OK  file {}B -> {} chunks x {}B plaintext", file.len(), n_chunks, CHUNK_PLAIN);

    let mut chunk_desc: Vec<(Vec<u8>, Vec<u8>, [u8; 32])> = Vec::new(); // (senderId, rcvId, digest chunk)
    let mut chunk_rcv_keys: Vec<SigningKey> = Vec::new();
    let mut chunk_snd_keys: Vec<SigningKey> = Vec::new();
    for ci in 0..n_chunks {
        let plain = &file[ci * CHUNK_PLAIN..((ci + 1) * CHUNK_PLAIN).min(file.len())];
        // последний chunk добиваем padding до CHUNK_PLAIN (фиксированный размер пакета)
        let mut padded = plain.to_vec();
        padded.resize(CHUNK_PLAIN, 0x00);
        let enc = sb_encrypt(&file_key, &chunk_nonce(&file_nonce, ci), &padded);
        assert_eq!(enc.len(), CHUNK_PLAIN + 16);
        let digest: [u8; 32] = sha2::Sha256::digest(&enc).into();

        let snd = SigningKey::from_bytes(&crypto::random_bytes(32).try_into().unwrap());
        let rcv = SigningKey::from_bytes(&crypto::random_bytes(32).try_into().unwrap());
        let mut cmd = b"FNEW ".to_vec();
        let snd_spki = spki_ed25519(&snd.verifying_key());
        cmd.push(snd_spki.len() as u8);
        cmd.extend_from_slice(&snd_spki);
        cmd.extend_from_slice(&(enc.len() as u32).to_be_bytes());
        cmd.push(32u8);
        cmd.extend_from_slice(&digest);
        let rcv_spki = spki_ed25519(&rcv.verifying_key());
        cmd.push(1u8);
        cmd.push(rcv_spki.len() as u8);
        cmd.extend_from_slice(&rcv_spki);
        cmd.push(b'0');
        cmd.push(b'0');
        let c = corr();
        let t = transmission(&session_id, &c, b"", &cmd);
        let sig = snd.sign(&t);
        let mut auth = vec![64u8];
        auth.extend_from_slice(&sig.to_bytes());
        let fr = post(&mut h2, Bytes::from(batch_block(&auth, &t)), &host).await;
        let pl = u16::from_be_bytes([fr[0], fr[1]]) as usize;
        let fp = &fr[2..(2 + pl).min(fr.len())];
        let pos = match fp.windows(4).position(|w| w == b"SIDS") {
            Some(p) => p,
            None => {
                println!("FAIL chunk {ci}: no SIDS: {}", show_resp(&fr));
                std::process::exit(1);
            }
        };
        let mut p = pos + 5;
        let sidl = fp[p] as usize;
        p += 1;
        let sender_id = fp[p..p + sidl].to_vec();
        p += sidl;
        let nrcv = fp[p] as usize;
        p += 1;
        let ridl = fp[p] as usize;
        p += 1;
        let rcv_id = fp[p..p + ridl].to_vec();
        assert_eq!(nrcv, 1);
        println!("OK  chunk {ci}: FNEW -> SIDS senderId({}B) rcvId({}B)", sender_id.len(), rcv_id.len());

        // FPUT chunk body
        let c = corr();
        let t = transmission(&session_id, &c, &sender_id, b"FPUT");
        let sig = snd.sign(&t);
        let mut auth = vec![64u8];
        auth.extend_from_slice(&sig.to_bytes());
        let mut blk = batch_block(&auth, &t);
        blk.extend_from_slice(&enc);
        let pr = post(&mut h2, Bytes::from(blk), &host).await;
        if !pr.windows(2).any(|w| w == b"OK") {
            println!("FAIL chunk {ci} FPUT: {}", show_resp(&pr));
            std::process::exit(1);
        }
        println!("OK  chunk {ci}: FPUT -> OK ({}B)", enc.len());
        chunk_desc.push((sender_id, rcv_id, digest));
        chunk_rcv_keys.push(rcv);
        chunk_snd_keys.push(snd);
    }

    // ---- chunked download (recipient) ----
    let mut assembled = Vec::new();
    for ci in 0..n_chunks {
        let rcv = &chunk_rcv_keys[ci];
        let (_, rcv_id, _) = &chunk_desc[ci];
        let r_dh = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let rdh_spki = spki_x25519(X25519Public::from(&r_dh).as_bytes());
        let mut cmd = b"FGET ".to_vec();
        cmd.push(rdh_spki.len() as u8);
        cmd.extend_from_slice(&rdh_spki);
        let c = corr();
        let t = transmission(&session_id, &c, rcv_id, &cmd);
        let sig = rcv.sign(&t);
        let mut auth = vec![64u8];
        auth.extend_from_slice(&sig.to_bytes());
        let gr = post(&mut h2, Bytes::from(batch_block(&auth, &t)), &host).await;
        if gr.len() < BLOCK + 16 {
            println!("FAIL chunk {ci} FGET short ({}B)", gr.len());
            std::process::exit(1);
        }
        let pl = u16::from_be_bytes([gr[0], gr[1]]) as usize;
        let head = &gr[2..(2 + pl).min(gr.len())];
        let pos = head.windows(4).rposition(|w| w == b"FILE").expect("FILE");
        let mut p = pos + 5;
        let sl = head[p] as usize;
        p += 1;
        let sdh_spki = &head[p..p + sl];
        p += sl;
        let cb_nonce: [u8; 24] = head[p..p + 24].try_into().unwrap();
        let s_dh_pub = X25519Public::from(<[u8; 32]>::try_from(&sdh_spki[sdh_spki.len() - 32..]).unwrap());
        let dh_secret = r_dh.diffie_hellman(&s_dh_pub);
        let enc_body = &gr[BLOCK..];
        let body = {
            let k = nexxrust::protocols::smp::crypto_box_beforenm(dh_secret.as_bytes());
            sb_decrypt_tail_tag(&k, &cb_nonce, enc_body)
                .or_else(|_| sb_decrypt(&k, &cb_nonce, enc_body))
                .or_else(|_| sb_decrypt_tail_tag(dh_secret.as_bytes(), &cb_nonce, enc_body))
                .expect("outer cb decrypt")
        };
        let plain = sb_decrypt(&file_key, &chunk_nonce(&file_nonce, ci), &body).expect("inner sb decrypt");
        assert_eq!(plain.len(), CHUNK_PLAIN);
        assembled.extend_from_slice(&plain[..CHUNK_PLAIN.min(file.len() - ci * CHUNK_PLAIN)]);
        println!("OK  chunk {ci}: FGET -> FILE, decrypted {}B", plain.len());
    }
    if assembled != file {
        println!("FAIL assembled mismatch ({} vs {}B)", assembled.len(), file.len());
        std::process::exit(1);
    }
    let got_sha512 = sha2::Sha512::digest(&assembled);
    if got_sha512[..] != file_sha512[..] {
        println!("FAIL whole-file SHA512 mismatch");
        std::process::exit(1);
    }
    println!("OK  whole-file SHA512 matches ({}B file)", file.len());
    println!("OK  file description: {} chunks, whole-file digest sha512={}", n_chunks, crypto::base64url_encode(&file_sha512));

    // ---- FDEL всех chunk'ов ----
    for ci in 0..n_chunks {
        let (sender_id, _, _) = &chunk_desc[ci];
        // нужен snd-ключ chunk'а — хранили в chunk_snd_keys
        let snd = &chunk_snd_keys[ci];
        let c = corr();
        let t = transmission(&session_id, &c, sender_id, b"FDEL");
        let sig = snd.sign(&t);
        let mut auth = vec![64u8];
        auth.extend_from_slice(&sig.to_bytes());
        let dr = post(&mut h2, Bytes::from(batch_block(&auth, &t)), &host).await;
        if !dr.windows(2).any(|w| w == b"OK") {
            println!("FAIL chunk {ci} FDEL: {}", show_resp(&dr));
            std::process::exit(1);
        }
    }
    println!("OK  FDEL all {} chunks", n_chunks);
    println!("=== XFTP CHUNKED INTEROP OK ({} chunks, {}B) ===", n_chunks, file.len());
}
