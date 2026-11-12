//! Крипто: SHA-256, PBKDF2-HMAC-SHA256, AES-256-GCM, base64url.
//! Чистые функции — тестируются на host через `cargo test`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// SHA-256, hex-строка (нижний регистр).
pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&sha256_raw(data))
}

/// SHA-256, сырые байты.
pub fn sha256_raw(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

/// PBKDF2-HMAC-SHA256 (RFC 2898), dk_len байт.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; dk_len];
    let _ = pbkdf2::pbkdf2::<HmacSha256>(password, salt, iterations, &mut out);
    out
}

/// PBKDF2-HMAC-SHA512 (RFC 2898) — **стандартный** KDF для BIP39 (2048 итераций).
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; dk_len];
    let _ = pbkdf2::pbkdf2::<HmacSha512>(password, salt, iterations, &mut out);
    out
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC принимает ключ любой длины");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// HKDF-Extract (RFC 5869): PRK = HMAC(salt, IKM). Пустая соль → 32 нулевых байта.
pub fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let zeros = [0u8; 32];
    let salt = if salt.is_empty() { &zeros } else { salt };
    let prk = hmac_sha256(salt, ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// HKDF-Expand (RFC 5869): OKM длиной `len` байт.
pub fn hkdf_sha256_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(len + 32);
    let mut block: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < len {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk)
            .expect("HMAC принимает ключ любой длины");
        mac.update(&block);
        mac.update(info);
        mac.update(&[counter]);
        block = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// AES-256-GCM encrypt: возвращает iv(12) + ciphertext + tag.
pub fn aes256_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("key must be 32 bytes".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("encrypt failed: {e}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-256-GCM decrypt: input = iv(12) + ciphertext + tag(16).
pub fn aes256_gcm_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("key must be 32 bytes".into());
    }
    if data.len() < 12 + 16 {
        return Err("ciphertext too short".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let (nonce_bytes, ct) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct).map_err(|_| "decrypt failed (bad key or tampered data)".into())
}

/// Случайные байты (CSPRNG платформы).
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut v);
    v
}

/// base64 (стандартный, с padding) decode — для vmess://.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    STANDARD
        .decode(s)
        .or_else(|_| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')))
        .map_err(|e| format!("base64 decode: {e}"))
}

/// base64url без padding decode — для ss:// (SIP002).
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| format!("base64url decode: {e}"))
}

pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// percent-decode (query string): %XX → байт, '+' → пробел.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 3 <= bytes.len() => {
                if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                    if let Ok(b) = u8::from_str_radix(hex, 16) {
                        out.push(b);
                        i += 3;
                        continue;
                    }
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// hex → байты. Нечётная длина или не-hex символ → None.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let t: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !t.len().is_multiple_of(2) {
        return None;
    }
    let bytes = t.as_bytes();
    let mut out = Vec::with_capacity(t.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Разбор query string в пары (percent-decoded значения).
pub fn parse_query_string(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = percent_decode(it.next().unwrap_or(""));
            let v = percent_decode(it.next().unwrap_or(""));
            (k, v)
        })
        .collect()
}

// OsRng используется через rand::rngs::OsRng в random_bytes.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn pbkdf2_rfc_vector() {
        // PBKDF2-HMAC-SHA256("password","salt",1,32) — известный вектор
        let dk = pbkdf2_hmac_sha256(b"password", b"salt", 1, 32);
        assert_eq!(
            hex_encode(&dk),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        // c=2
        let dk2 = pbkdf2_hmac_sha256(b"password", b"salt", 2, 32);
        assert_eq!(
            hex_encode(&dk2),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let key = random_bytes(32);
        let pt = "hello nexx, это секретное сообщение".as_bytes();
        let ct = aes256_gcm_encrypt(&key, pt).unwrap();
        assert_eq!(ct.len(), 12 + pt.len() + 16);
        let back = aes256_gcm_decrypt(&key, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn aes_gcm_tamper_detected() {
        let key = random_bytes(32);
        let mut ct = aes256_gcm_encrypt(&key, b"data").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(aes256_gcm_decrypt(&key, &ct).is_err());
    }

    #[test]
    fn aes_gcm_nist_vector() {
        // NIST GCM AES-256: key=0, iv=0, pt=0^128 → ct+tag = cea7403d...ab919
        let key = [0u8; 32];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let pt = [0u8; 16];
        let ct = cipher.encrypt(nonce, &pt[..]).unwrap();
        assert_eq!(hex_encode(&ct), "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
    }

    #[test]
    fn base64url_roundtrip() {
        let data = b"aes-256-gcm:secret\x01\x02";
        let enc = base64url_encode(data);
        let dec = base64url_decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn percent_decode_works() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
    }
}
