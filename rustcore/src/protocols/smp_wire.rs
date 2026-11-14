//! SMP wire-format (simplex-chat/simplexmq, protocol/simplex-messaging.md v20).
//!
//! Реализованы только примитивы кодирования и кадры, проверенные байт-в-байт
//! против живого `smp-server` v6.5.0 (см. скилл `simplex-smp-wire-protocol`).
//!
//! КРИТИЧНО: `Maybe` кодируется как `'0'`/`'1'`, `Bool` — как `'T'`/`'F'`.
//! Путаница этих тегов приводит к тому, что сервер молча рвёт соединение.

use crate::crypto::sha256_raw;

/// Фиксированный размер блока SMP.
pub const BLOCK_SIZE: usize = 16384;
/// Длина corrId (nonce) в байтах.
pub const CORR_ID_LEN: usize = 24;
/// Длина keyHash (SHA-256 от полного X.509 DER) в байтах.
pub const KEY_HASH_LEN: usize = 32;
/// ALPN для SMP-транспорта.
pub const ALPN_SMP: &[u8] = b"smp/1";
/// Минимальная версия протокола, где `authPubKey` в client hello = пустые байты.
pub const MIN_VERSION_AUTH_PUB_EMPTY: u16 = 7;
/// Версия, с которой в client hello приходит флаг `proxyServer`.
pub const MIN_VERSION_PROXY_SERVER: u16 = 14;
/// Версия, с которой в client hello приходит `clientService` (Maybe).
pub const MIN_VERSION_CLIENT_SERVICE: u16 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmpError {
    /// Неожиданный конец буфера.
    Eof,
    /// Ожидаемая длина не совпала.
    BadLength {
        expected: Option<usize>,
        got: usize,
    },
    /// Неверный тег ('0'/'1' против 'T'/'F').
    InvalidTag {
        what: &'static str,
        got: u8,
    },
    /// Содержимое не помещается в блок 16384 байта.
    BlockTooLong(usize),
    /// Неверный base64url.
    InvalidBase64(String),
    /// Ошибка криптографии (аутентификация не прошла и т.п.).
    Crypto(String),
}

impl std::fmt::Display for SmpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmpError::Eof => write!(f, "unexpected end of buffer"),
            SmpError::BadLength { expected, got } => {
                write!(f, "bad length: expected {expected:?}, got {got}")
            }
            SmpError::InvalidTag { what, got } => {
                write!(f, "invalid {what} tag: 0x{got:02x}")
            }
            SmpError::BlockTooLong(n) => write!(f, "content too long for SMP block: {n}"),
            SmpError::InvalidBase64(e) => write!(f, "invalid base64url: {e}"),
            SmpError::Crypto(e) => write!(f, "crypto error: {e}"),
        }
    }
}

impl std::error::Error for SmpError {}

// ---------------------------------------------------------------------------
// Примитивы кодирования
// ---------------------------------------------------------------------------

/// Word16, big-endian.
pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Word32, big-endian.
pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// ByteString: 1-байтная длина + данные (максимум 255 байт).
pub fn put_short(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SmpError> {
    if bytes.len() > 255 {
        return Err(SmpError::BadLength {
            expected: Some(255),
            got: bytes.len(),
        });
    }
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    Ok(())
}

/// Large: 2-байтная длина (big-endian) + данные.
pub fn put_large(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Bool: 'T' / 'F'.
pub fn put_bool(out: &mut Vec<u8>, v: bool) {
    out.push(if v { b'T' } else { b'F' });
}

/// Maybe: '0' = Nothing, '1' + значение = Just.
pub fn put_maybe_none(out: &mut Vec<u8>) {
    out.push(b'0');
}

/// Maybe: '1' + значение = Just.
pub fn put_maybe_some(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b'1');
    out.extend_from_slice(bytes);
}

/// Декодер с последовательным чтением.
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Decoder { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], SmpError> {
        if self.remaining() < n {
            return Err(SmpError::Eof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, SmpError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, SmpError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, SmpError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// ByteString: 1-байтная длина + данные.
    pub fn short(&mut self) -> Result<&'a [u8], SmpError> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    /// Large: 2-байтная длина + данные.
    pub fn large(&mut self) -> Result<&'a [u8], SmpError> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    /// Bool: 'T' / 'F'. Любой другой байт — ошибка (в т.ч. '0'/'1' от Maybe).
    pub fn bool(&mut self) -> Result<bool, SmpError> {
        match self.u8()? {
            b'T' => Ok(true),
            b'F' => Ok(false),
            other => Err(SmpError::InvalidTag {
                what: "bool",
                got: other,
            }),
        }
    }

    /// Maybe: '0' = None, '1' + ByteString = Some.
    pub fn maybe(&mut self) -> Result<Option<&'a [u8]>, SmpError> {
        match self.u8()? {
            b'0' => Ok(None),
            b'1' => Ok(Some(self.short()?)),
            other => Err(SmpError::InvalidTag {
                what: "maybe",
                got: other,
            }),
        }
    }

    /// Tail: остаток буфера без префикса длины.
    pub fn tail(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }
}

// ---------------------------------------------------------------------------
// Блоки и батчи
// ---------------------------------------------------------------------------

/// Кодирует содержимое в блок 16384 байта: `u16 len | content | '#'-padding`.
pub fn encode_block(content: &[u8]) -> Result<Vec<u8>, SmpError> {
    if content.len() + 2 > BLOCK_SIZE {
        return Err(SmpError::BlockTooLong(content.len()));
    }
    let mut out = Vec::with_capacity(BLOCK_SIZE);
    put_u16(&mut out, content.len() as u16);
    out.extend_from_slice(content);
    out.resize(BLOCK_SIZE, b'#');
    Ok(out)
}

/// Декодирует блок: возвращает содержимое без padding.
pub fn decode_block(block: &[u8]) -> Result<Vec<u8>, SmpError> {
    if block.len() < 2 {
        return Err(SmpError::Eof);
    }
    let len = u16::from_be_bytes([block[0], block[1]]) as usize;
    if len + 2 > block.len() {
        return Err(SmpError::BadLength {
            expected: Some(block.len() - 2),
            got: len,
        });
    }
    Ok(block[2..2 + len].to_vec())
}

/// Батч команд внутри блока: `u8 count | Large(transmission) * count`.
pub fn encode_batch(items: &[Vec<u8>]) -> Result<Vec<u8>, SmpError> {
    if items.len() > 255 {
        return Err(SmpError::BadLength {
            expected: Some(255),
            got: items.len(),
        });
    }
    let mut out = Vec::new();
    out.push(items.len() as u8);
    for it in items {
        put_large(&mut out, it);
    }
    Ok(out)
}

/// Декодирует батч команд.
pub fn decode_batch(buf: &[u8]) -> Result<Vec<Vec<u8>>, SmpError> {
    let mut d = Decoder::new(buf);
    let count = d.u8()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(d.large()?.to_vec());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// Server hello: диапазон версий, session id и публичные ключи авторизации.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub min_version: u16,
    pub max_version: u16,
    /// На TLS 1.3 session id непустой (32 байта) — участвует в подписи.
    pub session_id: Vec<u8>,
    pub auth_pub_keys: Vec<Vec<u8>>,
}

/// Разбирает server hello.
pub fn decode_server_hello(block: &[u8]) -> Result<ServerHello, SmpError> {
    let mut d = Decoder::new(block);
    let min_version = d.u16()?;
    let max_version = d.u16()?;
    let session_id = d.short()?.to_vec();
    let mut auth_pub_keys = Vec::new();
    while !d.is_empty() {
        auth_pub_keys.push(d.short()?.to_vec());
    }
    Ok(ServerHello {
        min_version,
        max_version,
        session_id,
        auth_pub_keys,
    })
}

/// Клиентский hello.
#[derive(Debug, Clone)]
pub struct ClientHello<'a> {
    pub version: u16,
    /// Сырые 32 байта SHA-256 от полного X.509 DER сертификата.
    pub key_hash: &'a [u8],
    /// `None` для v>=7 означает **пустые байты**, а не тег `'0'`.
    pub auth_pub_key: Option<&'a [u8]>,
    /// v>=14.
    pub proxy_server: bool,
    /// v>=16: Maybe — `None` = '0', `Some(kind)` = '1' + байт.
    pub client_service: Option<u8>,
}

/// Кодирует client hello.
pub fn encode_client_hello(h: &ClientHello<'_>) -> Result<Vec<u8>, SmpError> {
    let mut out = Vec::new();
    put_u16(&mut out, h.version);
    if h.key_hash.len() != KEY_HASH_LEN {
        return Err(SmpError::BadLength {
            expected: Some(KEY_HASH_LEN),
            got: h.key_hash.len(),
        });
    }
    put_short(&mut out, h.key_hash)?;
    match h.auth_pub_key {
        // v>=7: Nothing кодируется как НОЛЬ байт, а не как '0'.
        None => {}
        Some(k) => put_short(&mut out, k)?,
    }
    if h.version >= MIN_VERSION_PROXY_SERVER {
        put_bool(&mut out, h.proxy_server);
    }
    if h.version >= MIN_VERSION_CLIENT_SERVICE {
        match h.client_service {
            None => out.push(b'0'),
            Some(kind) => {
                out.push(b'1');
                out.push(kind);
            }
        }
    }
    Ok(out)
}

/// keyHash = SHA-256 от полного X.509 DER сертификата (сырые байты).
pub fn key_hash(cert_der: &[u8]) -> Vec<u8> {
    sha256_raw(cert_der)
}

/// keyHash в виде base64url — так он записан в адресе `smp://<keyHash>@host`.
pub fn key_hash_b64url(cert_der: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(key_hash(cert_der))
}

// ---------------------------------------------------------------------------
// Transmission
// ---------------------------------------------------------------------------

/// Transmission (RawTransmission) для обычного клиента v>=7:
/// `authenticator | corrId | entityId | command`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmission<'a> {
    /// Пустой — неавторизованная команда; иначе сырая Ed25519-подпись (64 Б).
    pub authenticator: &'a [u8],
    pub corr_id: &'a [u8],
    pub entity_id: &'a [u8],
    pub command: &'a [u8],
}

impl<'a> Transmission<'a> {
    pub fn new(corr_id: &'a [u8], entity_id: &'a [u8], command: &'a [u8]) -> Self {
        Transmission {
            authenticator: b"",
            corr_id,
            entity_id,
            command,
        }
    }
}

/// Версия протокола, с которой transmission с непустым authenticator
/// содержит опциональную подпись сервиса (`serviceSig`) после authenticator
/// (см. simplexmq `serviceCertsSMPVersion = 16`, `transmissionP` в Protocol.hs).
pub const SERVICE_CERTS_VERSION: u16 = 16;

/// Кодирует transmission для версии протокола `version`.
///
/// При `version >= 16` и непустом authenticator после него идёт `serviceSig`
/// (`'0'` = нет подписи сервиса, `'1'` + shortString(подпись)) — без этого
/// сервер отвечает `ERR BLOCK`.
pub fn encode_transmission_v(version: u16, t: &Transmission<'_>) -> Result<Vec<u8>, SmpError> {
    let mut out = Vec::new();
    put_short(&mut out, t.authenticator)?;
    if version >= SERVICE_CERTS_VERSION && !t.authenticator.is_empty() {
        // serviceSig = Nothing (у нас нет сервисных credentials)
        out.push(b'0');
    }
    put_short(&mut out, t.corr_id)?;
    put_short(&mut out, t.entity_id)?;
    out.extend_from_slice(t.command);
    Ok(out)
}

/// Кодирует transmission (актуальная версия протокола, v>=16).
pub fn encode_transmission(t: &Transmission<'_>) -> Result<Vec<u8>, SmpError> {
    encode_transmission_v(20, t)
}

/// Разбирает transmission для версии протокола `version`.
///
/// При `version >= 16` и непустом authenticator пропускает байт `serviceSig`
/// (`'0'`, либо `'1'` + shortString).
pub fn decode_transmission_v(version: u16, buf: &[u8]) -> Result<Transmission<'_>, SmpError> {
    let mut d = Decoder::new(buf);
    let authenticator = d.short()?;
    if version >= SERVICE_CERTS_VERSION && !authenticator.is_empty() {
        let tag = d.u8()?;
        if tag == b'1' {
            let _sig = d.short()?;
        } else if tag != b'0' {
            return Err(SmpError::BadLength {
                expected: Some(b'0' as usize),
                got: tag as usize,
            });
        }
    }
    let corr_id = d.short()?;
    let entity_id = d.short()?;
    let command = d.tail();
    Ok(Transmission {
        authenticator,
        corr_id,
        entity_id,
        command,
    })
}

/// Разбирает transmission (актуальная версия протокола, v>=16).
pub fn decode_transmission(buf: &[u8]) -> Result<Transmission<'_>, SmpError> {
    decode_transmission_v(20, buf)
}

/// Байты, которые подписываются Ed25519-подписью команды:
/// `short(sessionId) | short(corrId) | short(entityId) | command`.
pub fn authorized_bytes(
    session_id: &[u8],
    corr_id: &[u8],
    entity_id: &[u8],
    command: &[u8],
) -> Result<Vec<u8>, SmpError> {
    let mut out = Vec::new();
    put_short(&mut out, session_id)?;
    put_short(&mut out, corr_id)?;
    put_short(&mut out, entity_id)?;
    out.extend_from_slice(command);
    Ok(out)
}

/// Неавторизованный PING: `short("") | short(24B corrId) | short("") | "PING"`.
pub fn encode_ping(corr_id: &[u8]) -> Result<Vec<u8>, SmpError> {
    let mut out = Vec::new();
    put_short(&mut out, b"")?;
    put_short(&mut out, corr_id)?;
    put_short(&mut out, b"")?;
    out.extend_from_slice(b"PING");
    Ok(out)
}

/// Новый случайный corrId (24 байта).
pub fn new_corr_id() -> Vec<u8> {
    use rand::RngCore;
    let mut v = vec![0u8; CORR_ID_LEN];
    rand::rngs::OsRng.fill_bytes(&mut v);
    v
}

/// Проверяет, что ответ — PONG.
pub fn is_pong(buf: &[u8]) -> bool {
    buf.ends_with(b"PONG")
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn word16_is_big_endian() {
        let mut out = Vec::new();
        put_u16(&mut out, 0x0011);
        assert_eq!(hex(&out), "0011");
        let mut d = Decoder::new(&[0x00, 0x11]);
        assert_eq!(d.u16().unwrap(), 0x0011);
    }

    #[test]
    fn client_hello_v17_vector() {
        // Проверенный вектор: `0011 <short kh> 46 30`
        let kh: Vec<u8> = (0u8..32).collect();
        let hello = encode_client_hello(&ClientHello {
            version: 17,
            key_hash: &kh,
            auth_pub_key: None,
            proxy_server: false,
            client_service: None,
        })
        .unwrap();
        let expect_prefix = format!("0011{:02x}", kh.len());
        assert!(hex(&hello).starts_with(&expect_prefix));
        // хвост: 'F' (proxyServer=false) + '0' (clientService=Nothing)
        assert!(hex(&hello).ends_with("4630"));
        // authPubKey = НОЛЬ байт: после keyHash сразу идёт 'F'
        assert_eq!(hello.len(), 2 + 1 + 32 + 2);
    }

    #[test]
    fn client_hello_omits_fields_below_versions() {
        let kh = [0u8; 32];
        let hello = encode_client_hello(&ClientHello {
            version: 7,
            key_hash: &kh,
            auth_pub_key: None,
            proxy_server: true,
            client_service: Some(1),
        })
        .unwrap();
        // v<14: нет proxyServer; v<16: нет clientService
        assert_eq!(hello.len(), 2 + 1 + 32);
    }

    #[test]
    fn ping_vector_matches_reference() {
        let corr: Vec<u8> = (1u8..=24).collect();
        let ping = encode_ping(&corr).unwrap();
        let expect = format!("0018{}{}{}", hex(&corr), "00", "50494e47");
        assert_eq!(hex(&ping), expect);
    }

    #[test]
    fn block_padding_and_roundtrip() {
        let content = b"PING".to_vec();
        let block = encode_block(&content).unwrap();
        assert_eq!(block.len(), BLOCK_SIZE);
        assert_eq!(decode_block(&block).unwrap(), content);
        // padding — символ '#'
        assert!(block[2 + content.len()..].iter().all(|&b| b == b'#'));
    }

    #[test]
    fn block_rejects_oversized_content() {
        let big = vec![0u8; BLOCK_SIZE];
        assert!(matches!(
            encode_block(&big),
            Err(SmpError::BlockTooLong(_))
        ));
    }

    #[test]
    fn batch_roundtrip() {
        let t1 = encode_transmission(&Transmission::new(b"corr", b"", b"PING")).unwrap();
        let t2 = encode_transmission(&Transmission::new(b"corr2", b"entity", b"SUB")).unwrap();
        let batch = encode_batch(&[t1.clone(), t2.clone()]).unwrap();
        assert_eq!(batch[0], 2);
        assert_eq!(decode_batch(&batch).unwrap(), vec![t1, t2]);
    }

    #[test]
    fn maybe_and_bool_tags_are_distinct() {
        let mut d = Decoder::new(b"0");
        assert_eq!(d.maybe().unwrap(), None);
        let mut d = Decoder::new(b"T");
        assert!(d.bool().unwrap());
        // '0' вместо Bool — ошибка (именно из-за этого сервер рвёт соединение)
        let mut d = Decoder::new(b"0");
        assert!(matches!(d.bool(), Err(SmpError::InvalidTag { .. })));
        // 'T' вместо Maybe — ошибка
        let mut d = Decoder::new(b"T");
        assert!(matches!(d.maybe(), Err(SmpError::InvalidTag { .. })));
    }

    #[test]
    fn transmission_roundtrip() {
        let cmd = b"SUB";
        let t = Transmission::new(b"0123456789abcdef01234567", b"entity-id", cmd);
        let bytes = encode_transmission(&t).unwrap();
        let back = decode_transmission(&bytes).unwrap();
        assert_eq!(back, t);
        assert_eq!(back.command, cmd);
    }

    #[test]
    fn service_sig_byte_present_for_signed_transmission_v16_plus() {
        // v>=16: после непустого authenticator идёт serviceSig ('0' = Nothing).
        // Без этого байта сервер (v>=16) отвечает ERR BLOCK — поймано живым прогоном.
        let auth = [0xABu8; 64];
        let t = Transmission {
            authenticator: &auth,
            corr_id: b"0123456789abcdef01234567",
            entity_id: b"",
            command: b"NEW ...",
        };
        let v20 = encode_transmission_v(20, &t).unwrap();
        // layout: 0x40 + 64 sig + '0' + 0x18 + 24 corr + 0x00 + cmd
        assert_eq!(v20[0], 64);
        assert_eq!(v20[65], b'0');
        assert_eq!(v20[66], 24);
        let back = decode_transmission_v(20, &v20).unwrap();
        assert_eq!(back.authenticator, &auth[..]);
        assert_eq!(back.corr_id, b"0123456789abcdef01234567");
        // v15: serviceSig отсутствует
        let v15 = encode_transmission_v(15, &t).unwrap();
        assert_eq!(v15[65], 24); // сразу corrId length
        // пустой authenticator (PING) — serviceSig нет даже на v20
        let ping = encode_transmission_v(20, &Transmission::new(b"0123456789abcdef01234567", b"", b"PING")).unwrap();
        assert_eq!(ping[0], 0);
        assert_eq!(ping[1], 24);
    }

    #[test]
    fn authorized_bytes_layout() {
        let b = authorized_bytes(b"sess", b"corr", b"ent", b"SUB").unwrap();
        assert_eq!(hex(&b), "047365737304636f727203656e74535542");
    }

    #[test]
    fn server_hello_decode() {
        let mut buf = Vec::new();
        put_u16(&mut buf, 6);
        put_u16(&mut buf, 18);
        put_short(&mut buf, &[0xAB; 32]).unwrap();
        put_short(&mut buf, &[0xCD; 44]).unwrap();
        let hello = decode_server_hello(&buf).unwrap();
        assert_eq!(hello.min_version, 6);
        assert_eq!(hello.max_version, 18);
        assert_eq!(hello.session_id.len(), 32);
        assert_eq!(hello.auth_pub_keys.len(), 1);
    }

    #[test]
    fn key_hash_is_sha256_of_cert_der() {
        // SHA-256 от пустой строки — контрольный вектор.
        let h = key_hash(b"");
        assert_eq!(
            hex(&h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // SPKI и полный DER дают разные keyHash — нельзя путать.
        assert_ne!(key_hash(b"spki"), key_hash(b"spki-more"));
    }
}
