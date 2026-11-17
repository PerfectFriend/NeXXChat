//! XFTP chunked file transfer (Этап 3) — библиотечная версия bin/xftp_chunk.rs.
//!
//! Один data packet 64KB → большие файлы режутся на chunk'и, каждый chunk —
//! отдельный FNEW/FPUT (свои snd/rcv ed25519 ключи), скачивание — FGET per chunk.
//! Внутренний слой: один fileKey на файл, nonce chunk'а = fileNonce[0..16] || be64(index).
//! FileDesc сериализуется в base64url — это "ссылка на файл", которую можно отправить в чат.
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use sha2::Digest;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::crypto;

pub const BLOCK: usize = 16384;
/// plaintext на chunk: 64KB packet = 65536 bodyPart, из них 16B tag secretbox.
pub const CHUNK_PLAIN: usize = 64 * 1024 - 16;

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
    crypto_secretbox::XSalsa20Poly1305::new(key.into())
        .encrypt(nonce.into(), crypto_secretbox::aead::Payload::from(msg))
        .expect("sb encrypt")
}
fn sb_decrypt(key: &[u8; 32], nonce: &[u8; 24], tag_ct: &[u8]) -> Result<Vec<u8>, String> {
    use crypto_secretbox::aead::{Aead, KeyInit};
    crypto_secretbox::XSalsa20Poly1305::new(key.into())
        .decrypt(nonce.into(), crypto_secretbox::aead::Payload::from(tag_ct))
        .map_err(|e| format!("sb decrypt: {e}"))
}
/// XFTP потоковый формат: ciphertext || tail-tag(16B) → tag || ct.
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
/// nonce chunk'а: fileNonce, младшие 8 байт = big-endian index.
pub fn chunk_nonce(file_nonce: &[u8; 24], index: usize) -> [u8; 24] {
    let mut n = *file_nonce;
    n[16..24].copy_from_slice(&(index as u64).to_be_bytes());
    n
}

/// Описание загруженного файла — уходит собеседнику как "ссылка" (base64url JSON-ish бинарник).
#[derive(Debug, Clone)]
pub struct FileDesc {
    pub host: String,
    pub port: u16,
    pub file_key: [u8; 32],
    pub file_nonce: [u8; 24],
    pub size: usize,
    pub sha512: Vec<u8>,
    /// per chunk: (sender_id, rcv_id, chunk digest, snd secret, rcv secret)
    pub chunks: Vec<ChunkDesc>,
}
#[derive(Debug, Clone)]
pub struct ChunkDesc {
    pub sender_id: Vec<u8>,
    pub rcv_id: Vec<u8>,
    pub digest: [u8; 32],
    pub snd_sec: [u8; 32],
    pub rcv_sec: [u8; 32],
}

impl FileDesc {
    pub fn encode(&self) -> String {
        let mut o = Vec::new();
        o.extend_from_slice(&(self.host.len() as u16).to_be_bytes());
        o.extend_from_slice(self.host.as_bytes());
        o.extend_from_slice(&self.port.to_be_bytes());
        o.extend_from_slice(&self.file_key);
        o.extend_from_slice(&self.file_nonce);
        o.extend_from_slice(&(self.size as u64).to_be_bytes());
        o.extend_from_slice(&(self.sha512.len() as u16).to_be_bytes());
        o.extend_from_slice(&self.sha512);
        o.push(self.chunks.len() as u8);
        for c in &self.chunks {
            o.push(c.sender_id.len() as u8);
            o.extend_from_slice(&c.sender_id);
            o.push(c.rcv_id.len() as u8);
            o.extend_from_slice(&c.rcv_id);
            o.extend_from_slice(&c.digest);
            o.extend_from_slice(&c.snd_sec);
            o.extend_from_slice(&c.rcv_sec);
        }
        format!("nexx://file#/{}", crypto::base64url_encode(&o))
    }
    pub fn decode(s: &str) -> Result<Self, String> {
        let payload = s.split("#/").nth(1).ok_or("нет payload после #/")?;
        let d = crypto::base64url_decode(payload)?;
        let mut p = 0usize;
        let hl = u16::from_be_bytes([*d.get(p).ok_or("EOF")? , *d.get(p + 1).ok_or("EOF")?]) as usize;
        p += 2;
        let host = String::from_utf8(d.get(p..p + hl).ok_or("EOF host")?.to_vec()).map_err(|e| e.to_string())?;
        p += hl;
        let port = u16::from_be_bytes([*d.get(p).ok_or("EOF")? , *d.get(p + 1).ok_or("EOF")?]);
        p += 2;
        let file_key: [u8; 32] = d.get(p..p + 32).ok_or("EOF key")?.try_into().map_err(|_| "key")?;
        p += 32;
        let file_nonce: [u8; 24] = d.get(p..p + 24).ok_or("EOF nonce")?.try_into().map_err(|_| "nonce")?;
        p += 24;
        let size = u64::from_be_bytes(d.get(p..p + 8).ok_or("EOF size")?.try_into().map_err(|_| "size")?) as usize;
        p += 8;
        let sl = u16::from_be_bytes([*d.get(p).ok_or("EOF")? , *d.get(p + 1).ok_or("EOF")?]) as usize;
        p += 2;
        let sha512 = d.get(p..p + sl).ok_or("EOF sha")?.to_vec();
        p += sl;
        let n = *d.get(p).ok_or("EOF chunks")? as usize;
        p += 1;
        let mut chunks = Vec::with_capacity(n);
        for _ in 0..n {
            let a = *d.get(p).ok_or("EOF")? as usize;
            p += 1;
            let sender_id = d.get(p..p + a).ok_or("EOF snd")?.to_vec();
            p += a;
            let b = *d.get(p).ok_or("EOF")? as usize;
            p += 1;
            let rcv_id = d.get(p..p + b).ok_or("EOF rcv")?.to_vec();
            p += b;
            let digest: [u8; 32] = d.get(p..p + 32).ok_or("EOF dg")?.try_into().map_err(|_| "dg")?;
            p += 32;
            let snd_sec: [u8; 32] = d.get(p..p + 32).ok_or("EOF ss")?.try_into().map_err(|_| "ss")?;
            p += 32;
            let rcv_sec: [u8; 32] = d.get(p..p + 32).ok_or("EOF rs")?.try_into().map_err(|_| "rs")?;
            p += 32;
            chunks.push(ChunkDesc { sender_id, rcv_id, digest, snd_sec, rcv_sec });
        }
        Ok(FileDesc { host, port, file_key, file_nonce, size, sha512, chunks })
    }
}

struct XftpConn {
    h2: h2::client::SendRequest<Bytes>,
    session_id: Vec<u8>,
    authority: String,
}

async fn post(h2: &mut h2::client::SendRequest<Bytes>, body: Bytes, authority: &str) -> Result<Bytes, String> {
    let req = http::Request::builder()
        .method("POST")
        .uri(format!("https://{authority}/"))
        .body(())
        .map_err(|e| e.to_string())?;
    let (resp, mut stream) = h2.send_request(req, false).map_err(|e| format!("h2 send: {e}"))?;
    stream.send_data(body, true).map_err(|e| format!("send_data: {e}"))?;
    let resp = tokio::time::timeout(std::time::Duration::from_secs(60), resp)
        .await
        .map_err(|_| "resp timeout".to_string())?
        .map_err(|e| format!("resp: {e}"))?;
    let status = resp.status();
    let mut rbody = resp.into_body();
    let mut data = Vec::new();
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(30), rbody.data()).await {
            Ok(Some(chunk)) => {
                let chunk = chunk.map_err(|e| e.to_string())?;
                let n = chunk.len();
                data.extend_from_slice(&chunk);
                let _ = rbody.flow_control().release_capacity(n);
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    if status != 200 {
        return Err(format!("HTTP {status}: {}", show_resp(&data)));
    }
    Ok(Bytes::from(data))
}

impl XftpConn {
    /// TLS1.3 + ALPN xftp/1 + обязательный пиннинг: expected_key_hash сравнивается
    /// constant-time с SHA-256(CA из предъявленной цепочки); при наличии ca_pem цепочка
    /// дополнительно валидируется через X509Store (как в SMP, C1). Без пина — отказ (K1).
    async fn connect(host: &str, port: u16, expected: &[[u8; 32]], _ca_pem: Option<&str>) -> Result<Self, String> {
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;

        builder.set_min_proto_version(Some(SslVersion::TLS1_3)).map_err(|e| e.to_string())?;
        builder
            .set_sigalgs_list("ed448:ed25519:ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512")
            .map_err(|e| e.to_string())?;
        builder.set_groups_list("X25519").map_err(|e| e.to_string())?;
        builder.set_alpn_protos(b"\x06xftp/1").map_err(|e| e.to_string())?;
        builder.set_verify(openssl::ssl::SslVerifyMode::NONE); // пиннинг по keyHash в clientHello (ниже)
        let connector = builder.build();
        let tcp = tokio::net::TcpStream::connect((host, port)).await.map_err(|e| format!("tcp: {e}"))?;
        let mut ssl_obj = openssl::ssl::Ssl::new(connector.context()).map_err(|e| e.to_string())?;
        ssl_obj.set_alpn_protos(b"\x06xftp/1").map_err(|e| e.to_string())?;
        let mut ssl = tokio_openssl::SslStream::new(ssl_obj, tcp).map_err(|e| e.to_string())?;
        {
            let mut pinned = std::pin::Pin::new(&mut ssl);
            pinned.as_mut().connect().await.map_err(|e| format!("tls: {e}"))?;
        }
        let alpn = ssl.ssl().selected_alpn_protocol().unwrap_or(b"").to_vec();
        if alpn != b"xftp/1" {
            return Err(format!("ALPN != xftp/1: {alpn:?}"));
        }
        let mut fin_buf = [0u8; 64];
        let fin_len = ssl.ssl().finished(&mut fin_buf);
        let session_id = fin_buf[..fin_len].to_vec();
        let chain = ssl.ssl().peer_cert_chain().ok_or("no peer chain")?;
        let chain_ders: Vec<Vec<u8>> = chain.iter().filter_map(|c| c.to_der().ok()).collect();
        if std::env::var("NEXX_DEBUG").is_ok() {
            for d in &chain_ders { eprintln!("chain cert sha256: {}", hex::encode(sha2::Sha256::digest(d))); }
            for p in expected { eprintln!("expected pin: {}", hex::encode(p)); }
        }
        let leaf_der = chain_ders.first().ok_or("empty chain")?.clone();
        // K1: обязателен пин — хотя бы один cert цепочки совпадает с закреплённым keyHash
        // (constant-time, any-of trust set). Без этого — отказ. X.509 verify ниже — best-effort.
        let pinned = !expected.is_empty() && expected.iter().any(|pin| {
            chain_ders.iter().any(|d| crate::protocols::smp_client::ct_eq(&sha2::Sha256::digest(d), pin))
        });
        if !pinned {
            return Err("XFTP K1: в цепочке нет CA с закреплённым keyHash (MITM?)".into());
        }
        // доп. глубина: X.509 валидация против trust store (не fatal — протокол XFTP пинит keyHash сам)
        {
            use openssl::stack::Stack;
            use openssl::x509::store::X509StoreBuilder;
            use openssl::x509::{X509, X509StoreContext};
            if let (Ok(leaf), Ok(mut b)) = (X509::from_der(&leaf_der), X509StoreBuilder::new()) {
                for pem in [include_str!("../../assets/xftp1-443-ca.pem"), include_str!("../../assets/xftp1-443-ca2.pem")] {
                    if let Ok(st) = X509::stack_from_pem(pem.as_bytes()) {
                        for c in st { let _ = b.add_cert(c); }
                    }
                }
                let store = b.build();
                if let Ok(mut untrusted) = Stack::new() {
                    for d in &chain_ders { if let Ok(c) = X509::from_der(d) { let _ = untrusted.push(c); } }
                    if let Ok(mut ctx) = X509StoreContext::new() {
                        if let Ok(v) = ctx.init(&store, &leaf, &untrusted, |c| c.verify_cert()) {
                            if !v && std::env::var("NEXX_DEBUG").is_ok() { eprintln!("XFTP K1: x509 verify_cert=false (пин пройден)"); }
                        }
                    }
                }
            }
        }
        // XFTP keyHash = SHA-256(CA cert из цепочки сервера): берём intermediate (chain[1]), fallback last
        let ca_der = chain_ders.last().ok_or("no CA in chain")?.clone();
        let key_hash: [u8; 32] = sha2::Sha256::digest(&ca_der).into();
        if std::env::var("NEXX_DEBUG").is_ok() { eprintln!("clientHello keyHash: {}", hex::encode(key_hash)); }
        let (h2, conn) = h2::client::handshake(ssl).await.map_err(|e| format!("h2: {e}"))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut c = XftpConn { h2, session_id, authority: host.to_string() };
        c.post_raw(Bytes::new()).await?; // serverHello
        // парсим версию из serverHello
        // (ответ на пустой POST — serverHello block)
        // делаем clientHello
        let mut ch = Vec::new();
        ch.extend_from_slice(&4u16.to_be_bytes());
        ch.push(32u8);
        ch.extend_from_slice(&key_hash);
        ch.push(b'0');
        let chr = c.post_raw(Bytes::from(block(&ch))).await?;
        if !chr.is_empty() {
            return Err(format!("clientHello rejected: {}", show_resp(&chr)));
        }
        let t = transmission(&c.session_id, &corr(), b"", b"PING");
        let pr = c.post_raw(Bytes::from(batch_block(&[0u8], &t))).await?;
        if !pr.windows(4).any(|w| w == b"PONG") {
            return Err("no PONG".into());
        }
        Ok(c)
    }

    async fn post_raw(&mut self, body: Bytes) -> Result<Bytes, String> {
        post(&mut self.h2, body, &self.authority).await
    }

    async fn cmd(&mut self, entity: &[u8], cmd: &[u8], signer: Option<&SigningKey>) -> Result<Vec<u8>, String> {
        let t = transmission(&self.session_id.clone(), &corr(), entity, cmd);
        let auth = match signer {
            Some(s) => {
                let sig = s.sign(&t);
                let mut a = vec![64u8];
                a.extend_from_slice(&sig.to_bytes());
                a
            }
            None => vec![0u8],
        };
        let r = self.post_raw(Bytes::from(batch_block(&auth, &t))).await?;
        Ok(r.to_vec())
    }
}

/// keyHash (SHA-256 cert DER) доверенных CA публичного XFTP-релея xftp1.simplex.im:443.
/// Релей отдаёт разные LE-цепочки (YR2 / E-series) — trust set, any-of в connect (K1).
pub fn xftp1_key_hashes() -> Vec<[u8; 32]> {
    // DER-хеши CA из assets + хеши цепочек, реально отдаваемых xftp1 (YR2/Root YR и E-series без SNI)
    let mut out: Vec<[u8; 32]> = Vec::new();
    for pem in [include_str!("../../assets/xftp1-443-ca.pem"), include_str!("../../assets/xftp1-443-ca2.pem")] {
        if let Ok(stack) = openssl::x509::X509::stack_from_pem(pem.as_bytes()) {
            for ca in stack {
                if let Ok(der) = ca.to_der() { out.push(sha2::Sha256::digest(&der).into()); }
            }
        }
    }
    for h in ["75ad5a1f79ce4fef46f2557b6d66a6871a4361d275c665bb8f726919a0d1e548",
              "80b08f05cc32350c070f72aaf9eafc30a2e0875b53ff80896ea510d082b884a1"] {
        if let Ok(v) = hex::decode(h) { if let Ok(a) = <[u8; 32]>::try_from(v.as_slice()) { out.push(a); } }
    }
    out
}

/// Загружает файл chunked'ами на XFTP-релей. Возвращает FileDesc ("ссылку" для собеседника).
pub async fn upload_file(host: &str, port: u16, expected: &[[u8; 32]], data: &[u8]) -> Result<FileDesc, String> {
    let mut c = XftpConn::connect(host, port, expected, None).await?;
    let file_key: [u8; 32] = crypto::random_bytes(32).try_into().map_err(|_| "rng")?;
    let file_nonce: [u8; 24] = crypto::random_bytes(24).try_into().map_err(|_| "rng")?;
    let file_sha512 = sha2::Sha512::digest(data).to_vec();
    let n_chunks = data.len().div_ceil(CHUNK_PLAIN).max(1);
    let mut chunks = Vec::with_capacity(n_chunks);
    for ci in 0..n_chunks {
        let plain = &data[ci * CHUNK_PLAIN..((ci + 1) * CHUNK_PLAIN).min(data.len())];
        let mut padded = plain.to_vec();
        padded.resize(CHUNK_PLAIN, 0x00);
        let enc = sb_encrypt(&file_key, &chunk_nonce(&file_nonce, ci), &padded);
        let digest: [u8; 32] = sha2::Sha256::digest(&enc).into();
        let snd = SigningKey::from_bytes(&crypto::random_bytes(32).try_into().map_err(|_| "rng")?);
        let rcv = SigningKey::from_bytes(&crypto::random_bytes(32).try_into().map_err(|_| "rng")?);
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
        let fr = c.cmd(b"", &cmd, Some(&snd)).await?;
        let pl = u16::from_be_bytes([*fr.first().ok_or("EOF")? , *fr.get(1).ok_or("EOF")?]) as usize;
        let fp = fr.get(2..(2 + pl).min(fr.len())).ok_or("EOF SIDS")?;
        let pos = fp.windows(4).position(|w| w == b"SIDS").ok_or_else(|| format!("no SIDS: {}", show_resp(&fr)))?;
        let mut p = pos + 5;
        let sidl = *fp.get(p).ok_or("EOF")? as usize;
        p += 1;
        let sender_id = fp.get(p..p + sidl).ok_or("EOF")? .to_vec();
        p += sidl;
        let nrcv = *fp.get(p).ok_or("EOF")? as usize;
        p += 1;
        let ridl = *fp.get(p).ok_or("EOF")? as usize;
        p += 1;
        let rcv_id = fp.get(p..p + ridl).ok_or("EOF")?.to_vec();
        if nrcv != 1 {
            return Err("nrcv != 1".into());
        }
        // FPUT: одна transmission, подпись над ней, body дозаписываем после block
        let t = transmission(&c.session_id, &corr(), &sender_id, b"FPUT");
        let sig = snd.sign(&t);
        let mut auth = vec![64u8];
        auth.extend_from_slice(&sig.to_bytes());
        let mut blk = batch_block(&auth, &t);
        blk.extend_from_slice(&enc);
        let pr = c.post_raw(Bytes::from(blk)).await?;
        if !pr.windows(2).any(|w| w == b"OK") {
            return Err(format!("chunk {ci} FPUT: {}", show_resp(&pr)));
        }
        chunks.push(ChunkDesc {
            sender_id,
            rcv_id,
            digest,
            snd_sec: snd.to_bytes(),
            rcv_sec: rcv.to_bytes(),
        });
    }
    Ok(FileDesc {
        host: host.to_string(),
        port,
        file_key,
        file_nonce,
        size: data.len(),
        sha512: file_sha512,
        chunks,
    })
}

/// Скачивает файл по FileDesc и проверяет whole-file SHA512.
pub async fn download_file(desc: &FileDesc, expected: &[[u8; 32]]) -> Result<Vec<u8>, String> {
    let mut c = XftpConn::connect(&desc.host, desc.port, expected, None).await?;
    let mut assembled = Vec::with_capacity(desc.size);
    for (ci, ch) in desc.chunks.iter().enumerate() {
        let rcv = SigningKey::from_bytes(&ch.rcv_sec);
        let r_dh = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let rdh_spki = spki_x25519(X25519Public::from(&r_dh).as_bytes());
        let mut cmd = b"FGET ".to_vec();
        cmd.push(rdh_spki.len() as u8);
        cmd.extend_from_slice(&rdh_spki);
        let gr = c.cmd(&ch.rcv_id, &cmd, Some(&rcv)).await?;
        if gr.len() < BLOCK + 16 {
            return Err(format!("chunk {ci} FGET short ({}B)", gr.len()));
        }
        let pl = u16::from_be_bytes([gr[0], gr[1]]) as usize;
        let head = &gr[2..(2 + pl).min(gr.len())];
        let pos = head.windows(4).rposition(|w| w == b"FILE").ok_or("no FILE")?;
        let mut p = pos + 5;
        let sl = head[p] as usize;
        p += 1;
        let sdh_spki = &head[p..p + sl];
        p += sl;
        let cb_nonce: [u8; 24] = head.get(p..p + 24).ok_or("EOF nonce")?.try_into().map_err(|_| "nonce")?;
        let s_dh_pub = X25519Public::from(<[u8; 32]>::try_from(&sdh_spki[sdh_spki.len() - 32..]).map_err(|_| "sdh")?);
        let dh_secret = r_dh.diffie_hellman(&s_dh_pub);
        let enc_body = &gr[BLOCK..];
        let body = {
            let k = crate::protocols::smp::crypto_box_beforenm(dh_secret.as_bytes());
            sb_decrypt_tail_tag(&k, &cb_nonce, enc_body)
                .or_else(|_| sb_decrypt(&k, &cb_nonce, enc_body))
                .or_else(|_| sb_decrypt_tail_tag(dh_secret.as_bytes(), &cb_nonce, enc_body))
                .map_err(|e| format!("chunk {ci} outer decrypt: {e}"))?
        };
        let plain = sb_decrypt(&desc.file_key, &chunk_nonce(&desc.file_nonce, ci), &body)
            .map_err(|e| format!("chunk {ci} inner: {e}"))?;
        let take = CHUNK_PLAIN.min(desc.size - ci * CHUNK_PLAIN);
        assembled.extend_from_slice(&plain[..take]);
    }
    let got = sha2::Sha512::digest(&assembled);
    if got[..] != desc.sha512[..] {
        return Err("SHA512 mismatch".into());
    }
    Ok(assembled)
}

/// Удаляет все chunk'и файла (FDEL от имени отправителя).
pub async fn delete_file(desc: &FileDesc, expected: &[[u8; 32]]) -> Result<(), String> {
    let mut c = XftpConn::connect(&desc.host, desc.port, expected, None).await?;
    for ch in &desc.chunks {
        let snd = SigningKey::from_bytes(&ch.snd_sec);
        let r = c.cmd(&ch.sender_id, b"FDEL", Some(&snd)).await?;
        if !r.windows(2).any(|w| w == b"OK") {
            return Err(format!("FDEL: {}", show_resp(&r)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_desc_roundtrip() {
        let desc = FileDesc {
            host: "xftp1.simplex.im".into(),
            port: 443,
            file_key: [1u8; 32],
            file_nonce: [2u8; 24],
            size: 123456,
            sha512: vec![9u8; 64],
            chunks: vec![ChunkDesc {
                sender_id: vec![3u8; 16],
                rcv_id: vec![4u8; 16],
                digest: [5u8; 32],
                snd_sec: [6u8; 32],
                rcv_sec: [7u8; 32],
            }],
        };
        let s = desc.encode();
        assert!(s.starts_with("nexx://file#/"));
        let back = FileDesc::decode(&s).unwrap();
        assert_eq!(back.host, desc.host);
        assert_eq!(back.port, 443);
        assert_eq!(back.file_key, [1u8; 32]);
        assert_eq!(back.size, 123456);
        assert_eq!(back.chunks.len(), 1);
        assert_eq!(back.chunks[0].sender_id, vec![3u8; 16]);
        assert_eq!(back.chunks[0].rcv_sec, [7u8; 32]);
    }

    #[test]
    fn chunk_nonce_index_in_low_bytes() {
        let n = [7u8; 24];
        let c = chunk_nonce(&n, 5);
        assert_eq!(&c[..16], &[7u8; 16]);
        assert_eq!(&c[16..], &5u64.to_be_bytes());
    }
}
