//! SMP agent protocol (simplexmq, protocol/simplex-messaging.md v20).
//!
//! Реализовано по эталону Haskell-ядра `simplexmq` (~/xftp-research/simplexmq):
//!
//! * X.509/SPKI-энкодинг публичных ключей (Ed25519, X25519);
//! * `NEW`, `SUB`, `GET`, `ACK`, `DEL`, `OFF`, `SKEY`, `SEND` — точный ABNF;
//! * ответы `IDS`, `MSG`, `SOK`, `OK`, `ERR`, `PONG`;
//! * авторизация: Ed25519-подпись и deniable-authenticator
//!   (`crypto_box(sha512(t), nonce=corrId)`);
//! * шифрование тела сообщения: NaCl crypto_box (XSalsa20-Poly1305) поверх
//!   DH-секрета с pre-слоем HSalsa20(secret, 0^16), **с тегом впереди**;
//! * паддинг `word16(len) || msg || '#'` и цепочка ключей блоков
//!   `SimpleXSbChainInit` / `SimpleXSbChain` (HKDF-SHA512).
//!
//! КРИТИЧНО: порядок байт в secretbox — `tag(16) || ciphertext` (NaCl/libsodium).
//! Crate `crypto_secretbox` уже отдаёт этот порядок — переставлять НЕ надо
//! (KAT-проверено против libsodium crypto_box, см. тест crypto_box_kat_matches_simplexmq).

use crate::protocols::smp_wire::{put_short, put_u16, Decoder, SmpError};
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::XSalsa20Poly1305;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// Размер тела сообщения (до паддинга) для обычных сообщений.
pub const E2E_MSG_LEN: usize = 16000;
/// Размер тела сообщения для confirmation-сообщений.
pub const E2E_CONFIRMATION_LEN: usize = 15904;
/// Максимальный размер сообщения в байтах (v11+).
pub const MAX_MESSAGE_LENGTH: usize = 16048;
/// Версии протокола, влияющие на формат команд.
pub const AUTH_CMDS_VERSION: u16 = 7;
pub const SND_AUTH_KEY_VERSION: u16 = 9;
pub const ENCRYPTED_BLOCK_VERSION: u16 = 11;
pub const SHORT_LINKS_VERSION: u16 = 15;
pub const SERVICE_CERTS_VERSION: u16 = 16;
pub const NEW_NTF_CREDS_VERSION: u16 = 17;

/// SPKI-префикс Ed25519 (X.509 SubjectPublicKeyInfo).
pub const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// SPKI-префикс X25519 (X.509 SubjectPublicKeyInfo).
pub const X25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
];
/// SPKI-префикс Ed448 (X.509 SubjectPublicKeyInfo). Публичные релеи SimpleX
/// v7.1+ используют Ed448-сертификаты (и требуют ed448 в sigalgs ClientHello).
/// ВНИМАНИЕ: длина BIT STRING здесь 58 байт (0x3a), не 66 — релеи v7.1+ кладут
/// 58-байтный ключ; с префиксом 0x30 0x2f верификация падает.
pub const ED448_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00,
];

// ---------------------------------------------------------------------------
// X.509 / SPKI
// ---------------------------------------------------------------------------

/// Ed25519 public key -> X.509 DER.
pub fn ed25519_x509(pk: &[u8; 32]) -> Vec<u8> {
    let mut out = ED25519_SPKI_PREFIX.to_vec();
    out.extend_from_slice(pk);
    out
}

/// X25519 public key -> X.509 DER.
pub fn x25519_x509(pk: &[u8; 32]) -> Vec<u8> {
    let mut out = X25519_SPKI_PREFIX.to_vec();
    out.extend_from_slice(pk);
    out
}

/// Ищет в DER публичный ключ по SPKI-префиксу.
///
/// Допускает как «голый» 44-байтный SPKI, так и DER-сертификат, где
/// префикс встречается внутри (ищем первое вхождение).
pub fn parse_spki(der: &[u8], prefix: &[u8; 12]) -> Option<[u8; 32]> {
    let pos = der
        .windows(12)
        .position(|w| w == prefix.as_slice())?;
    if der.len() < pos + 44 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&der[pos + 12..pos + 44]);
    Some(key)
}

/// Ed25519 public key из DER (сертификат или SPKI).
pub fn parse_ed25519_x509(der: &[u8]) -> Option<[u8; 32]> {
    parse_spki(der, &ED25519_SPKI_PREFIX)
}

/// X25519 public key из DER (сертификат или SPKI).
pub fn parse_x25519_x509(der: &[u8]) -> Option<[u8; 32]> {
    parse_spki(der, &X25519_SPKI_PREFIX)
}

/// Ed448 public key (57 байт) из DER (сертификат или SPKI).
pub fn parse_ed448_x509(der: &[u8]) -> Option<[u8; 57]> {
    let pos = der
        .windows(12)
        .position(|w| w == ED448_SPKI_PREFIX.as_slice())?;
    if der.len() < pos + 69 {
        return None;
    }
    let mut key = [0u8; 57];
    key.copy_from_slice(&der[pos + 12..pos + 69]);
    Some(key)
}

// ---------------------------------------------------------------------------
// Паддинг и secretbox
// ---------------------------------------------------------------------------

/// Патчинг по simplexmq: `word16(len) || msg || '#' * (paddedLen - len - 2)`.
pub fn pad(msg: &[u8], padded_len: usize) -> Result<Vec<u8>, SmpError> {
    if msg.len() + 2 > padded_len {
        return Err(SmpError::BadLength {
            expected: Some(padded_len.saturating_sub(2)),
            got: msg.len(),
        });
    }
    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    out.resize(padded_len, b'#');
    Ok(out)
}

/// Обратный патчинг.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, SmpError> {
    if padded.len() < 2 {
        return Err(SmpError::Eof);
    }
    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if len + 2 > padded.len() {
        return Err(SmpError::BadLength {
            expected: None,
            got: len,
        });
    }
    Ok(padded[2..2 + len].to_vec())
}

// ---------------------------------------------------------------------------
// HSalsa20 и "beforenm"-слой Haskell-эталона
// ---------------------------------------------------------------------------

/// HSalsa20: ядро Salsa20 (20 раундов) без feedforward, выход — слова
/// 0,5,10,15,6,7,8,9. Точно как `Crypto.Cipher.XSalsa` в cryptonite / NaCl.
/// KAT-валидировано: см. тест `crypto_box_kat_matches_simplexmq`.
pub fn hsalsa20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]; // "expand 32-byte k"
    let k = |i: usize| u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    let n = |i: usize| u32::from_le_bytes([nonce[4 * i], nonce[4 * i + 1], nonce[4 * i + 2], nonce[4 * i + 3]]);
    let mut x = [
        SIGMA[0], k(0), k(1), k(2),
        k(3), SIGMA[1], n(0), n(1),
        n(2), n(3), SIGMA[2], k(4),
        k(5), k(6), k(7), SIGMA[3],
    ];
    macro_rules! qr {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            x[$b] ^= x[$a].wrapping_add(x[$d]).rotate_left(7);
            x[$c] ^= x[$b].wrapping_add(x[$a]).rotate_left(9);
            x[$d] ^= x[$c].wrapping_add(x[$b]).rotate_left(13);
            x[$a] ^= x[$d].wrapping_add(x[$c]).rotate_left(18);
        };
    }
    for _ in 0..10 {
        qr!(0, 4, 8, 12); qr!(5, 9, 13, 1); qr!(10, 14, 2, 6); qr!(15, 3, 7, 11);
        qr!(0, 1, 2, 3); qr!(5, 6, 7, 4); qr!(10, 11, 8, 9); qr!(15, 12, 13, 14);
    }
    let out = [x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9]];
    let mut r = [0u8; 32];
    for (i, w) in out.iter().enumerate() {
        r[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    r
}

/// Эквивалент первого слоя Haskell `xSalsa20` (Crypto.hs:1478):
/// `XSalsa.initialize 20 secret (zero16 <> iv0)` ≡ HSalsa20(secret, 0^16).
/// KAT: `cryptoBox secret nonce` == `secretbox(HSalsa20(secret,0^16), nonce)`
/// (сверено с cryptonite vectorsCB и libsodium crypto_box).
pub fn crypto_box_beforenm(secret: &[u8; 32]) -> [u8; 32] {
    hsalsa20(secret, &[0u8; 16])
}

/// NaCl `crypto_box` в формате simplexmq: `tag || ciphertext`.
/// Секрет (DH или симметричный ключ цепочки) сначала проходит через
/// HSalsa20(secret, 0^16) — как `cryptoBox` в Haskell-ядре simplexmq.
/// ВАЖНО: crate `crypto_secretbox` уже возвращает NaCl-порядок `tag || ct`
/// (проверено KAT против libsodium crypto_box) — переставлять НЕ надо.
pub fn crypto_box_encrypt(secret: &[u8; 32], nonce: &[u8; 24], msg: &[u8]) -> Vec<u8> {
    let k = crypto_box_beforenm(secret);
    let sb = XSalsa20Poly1305::new((&k).into());
    sb.encrypt(nonce.into(), crypto_secretbox::aead::Payload::from(msg))
        .expect("xsalsa20poly1305 encrypt")
}

/// Расшифровка `crypto_box` в формате simplexmq (`tag || ciphertext`).
pub fn crypto_box_decrypt(
    secret: &[u8; 32],
    nonce: &[u8; 24],
    packet: &[u8],
) -> Result<Vec<u8>, SmpError> {
    if packet.len() < 16 {
        return Err(SmpError::BadLength {
            expected: Some(16),
            got: packet.len(),
        });
    }
    let k = crypto_box_beforenm(secret);
    XSalsa20Poly1305::new((&k).into())
        .decrypt(nonce.into(), crypto_secretbox::aead::Payload::from(packet))
        .map_err(|_| SmpError::Crypto("secretbox: authentication failed".into()))
}

// ---------------------------------------------------------------------------
// HKDF-SHA512 и цепочка ключей блоков (v11+)
// ---------------------------------------------------------------------------

/// HKDF-SHA512 (RFC 5869) — как `Simplex.Messaging.Crypto.hkdf`.
pub fn hkdf_sha512(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = hkdf::Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).expect("hkdf expand");
    out
}

/// Ключ цепочки шифрования транспортных блоков.
#[derive(Clone)]
pub struct SbChainKey(pub [u8; 32]);

impl SbChainKey {
    /// Инициализация: `hkdf(sessionId, secret, "SimpleXSbChainInit", 64)`.
    pub fn init(session_id: &[u8], secret: &[u8; 32]) -> (SbChainKey, SbChainKey) {
        let out = hkdf_sha512(session_id, secret, b"SimpleXSbChainInit", 64);
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&out[..32]);
        k2.copy_from_slice(&out[32..64]);
        (SbChainKey(k1), SbChainKey(k2))
    }

    /// Следующий ключ+nonce цепочки: `hkdf("", ck, "SimpleXSbChain", 88)`.
    /// (Не Iterator::next — нам нужен следующий элемент конечной цепочки ключей.)
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> ([u8; 32], [u8; 24]) {
        let out = hkdf_sha512(&[], &self.0, b"SimpleXSbChain", 88);
        self.0.copy_from_slice(&out[..32]);
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&out[32..64]);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&out[64..88]);
        (sk, nonce)
    }
}

// ---------------------------------------------------------------------------
// Команды клиента
// ---------------------------------------------------------------------------

/// Ключи очереди получателя.
pub struct RecipientKeys {
    /// Ed25519-ключ для авторизации команд получателя.
    pub auth_signing: SigningKey,
    /// X25519-ключ для шифрования сообщений сервером.
    pub dh_secret: StaticSecret,
}

/// `NEW <rcvAuthKey> <rcvDhKey> <basicAuth> <subMode> [queueReqData] [ntfCreds]`.
/// queueReqData: `"1M0"` = Just(QRMessaging Nothing) — обязателен для работы SKEY
/// (иначе queueMode=None и allowedKey для SKEY падает в AUTH).
pub fn cmd_new(
    version: u16,
    rcv_auth_x509: &[u8],
    rcv_dh_x509: &[u8],
    basic_auth: Option<&[u8]>,
    subscribe: bool,
    queue_req_data: Option<&[u8]>,
    ntf_creds: Option<(&[u8], &[u8])>,
) -> Result<Vec<u8>, SmpError> {
    let mut out = Vec::new();
    out.extend_from_slice(b"NEW ");
    put_short(&mut out, rcv_auth_x509)?;
    put_short(&mut out, rcv_dh_x509)?;
    if version >= SND_AUTH_KEY_VERSION {
        match basic_auth {
            None => out.push(b'0'),
            Some(pw) => {
                out.push(b'1');
                put_short(&mut out, pw)?;
            }
        }
        out.push(if subscribe { b'S' } else { b'C' });
        if version >= SHORT_LINKS_VERSION {
            match queue_req_data {
                None => out.push(b'0'),
                Some(data) => {
                    out.push(b'1');
                    out.extend_from_slice(data);
                }
            }
            if version >= NEW_NTF_CREDS_VERSION {
                match ntf_creds {
                    None => out.push(b'0'),
                    Some((k, dh)) => {
                        out.push(b'1');
                        put_short(&mut out, k)?;
                        put_short(&mut out, dh)?;
                    }
                }
            }
        } else {
            // v9..v14: senderCanSecure (Bool)
            out.push(b'F');
        }
    } else {
        // v<9: старый стиль basic auth — 'A' + short(password)
        if let Some(pw) = basic_auth {
            out.push(b'A');
            put_short(&mut out, pw)?;
        }
        out.push(if subscribe { b'S' } else { b'C' });
    }
    Ok(out)
}

/// `SUB`
pub fn cmd_sub() -> Vec<u8> {
    b"SUB".to_vec()
}

/// `GET`
pub fn cmd_get() -> Vec<u8> {
    b"GET".to_vec()
}

/// `ACK <msgId>`
pub fn cmd_ack(msg_id: &[u8]) -> Result<Vec<u8>, SmpError> {
    let mut out = Vec::new();
    out.extend_from_slice(b"ACK ");
    put_short(&mut out, msg_id)?;
    Ok(out)
}

/// `DEL`
pub fn cmd_del() -> Vec<u8> {
    b"DEL".to_vec()
}

/// `OFF`
pub fn cmd_off() -> Vec<u8> {
    b"OFF".to_vec()
}

/// `SKEY <senderAuthKey>`
/// ВАЖНО: сервер примет SKEY только если очередь создана с queueMode=QMMessaging
/// (в NEW передать queueReqData = "1M0"), иначе ответ `ERR AUTH`.
/// Подписывается НОВЫМ ключом отправителя (а не старым ключом получателя).
pub fn cmd_skey(sender_auth_x509: &[u8]) -> Result<Vec<u8>, SmpError> {
    let mut out = Vec::new();
    out.extend_from_slice(b"SKEY ");
    put_short(&mut out, sender_auth_x509)?;
    Ok(out)
}

/// `KEY <senderAuthKey>` (v<9)
pub fn cmd_key(sender_auth_x509: &[u8]) -> Result<Vec<u8>, SmpError> {
    let mut out = Vec::new();
    out.extend_from_slice(b"KEY ");
    put_short(&mut out, sender_auth_x509)?;
    Ok(out)
}

/// `SEND <T|F> <envelope>`
pub fn cmd_send(notification: bool, envelope: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"SEND ");
    out.push(if notification { b'T' } else { b'F' });
    out.push(b' ');
    out.extend_from_slice(envelope);
    out
}

// ---------------------------------------------------------------------------
// Ответы сервера
// ---------------------------------------------------------------------------

/// Идентификаторы очереди из ответа `IDS`.
#[derive(Debug, Clone)]
pub struct QueueIds {
    pub rcv_id: Vec<u8>,
    pub snd_id: Vec<u8>,
    /// X.509 X25519 public key сервера для этой очереди.
    pub srv_dh_x509: Vec<u8>,
    /// Сервер разрешает отправителю защитить очередь (SKEY).
    pub sender_can_secure: bool,
}

/// Разбор ответа `IDS`.
pub fn parse_ids(version: u16, cmd: &[u8]) -> Result<QueueIds, SmpError> {
    if !cmd.starts_with(b"IDS ") {
        return Err(SmpError::InvalidTag {
            what: "IDS",
            got: cmd.first().copied().unwrap_or(0),
        });
    }
    let mut d = Decoder::new(&cmd[4..]);
    let rcv_id = d.short()?.to_vec();
    let snd_id = d.short()?.to_vec();
    let srv_dh_x509 = d.short()?.to_vec();
    let mut sender_can_secure = false;
    if version >= SHORT_LINKS_VERSION {
        // queueMode / linkId / serviceId — опциональны, на ответ не влияют.
    } else if version >= SND_AUTH_KEY_VERSION {
        sender_can_secure = d.bool()?;
    }
    Ok(QueueIds {
        rcv_id,
        snd_id,
        srv_dh_x509,
        sender_can_secure,
    })
}

/// Сообщение `MSG <msgId> <encryptedBody>`.
#[derive(Debug, Clone)]
pub struct RcvMessage {
    pub msg_id: Vec<u8>,
    pub body: Vec<u8>,
}

/// Разбор ответа `MSG`.
pub fn parse_msg(cmd: &[u8]) -> Result<RcvMessage, SmpError> {
    if !cmd.starts_with(b"MSG ") {
        return Err(SmpError::InvalidTag {
            what: "MSG",
            got: cmd.first().copied().unwrap_or(0),
        });
    }
    let mut d = Decoder::new(&cmd[4..]);
    let msg_id = d.short()?.to_vec();
    let body = d.tail().to_vec();
    Ok(RcvMessage { msg_id, body })
}

/// Ответ сервера, который нас интересует.
#[derive(Debug, Clone)]
pub enum ServerResponse {
    Ok,
    Err(String),
    Sok,
    Pong,
    Ids(QueueIds),
    Msg(RcvMessage),
    Other(Vec<u8>),
}

/// Разбор общей команды сервера.
pub fn parse_response(version: u16, cmd: &[u8]) -> ServerResponse {
    if cmd.starts_with(b"OK") {
        ServerResponse::Ok
    } else if cmd.starts_with(b"ERR ") {
        ServerResponse::Err(String::from_utf8_lossy(&cmd[4..]).to_string())
    } else if cmd.starts_with(b"SOK") {
        ServerResponse::Sok
    } else if cmd.starts_with(b"PONG") {
        ServerResponse::Pong
    } else if cmd.starts_with(b"IDS ") {
        match parse_ids(version, cmd) {
            Ok(ids) => ServerResponse::Ids(ids),
            Err(e) => ServerResponse::Other(format!("ERR parse IDS: {e}").into_bytes()),
        }
    } else if cmd.starts_with(b"MSG ") {
        match parse_msg(cmd) {
            Ok(m) => ServerResponse::Msg(m),
            Err(e) => ServerResponse::Other(format!("ERR parse MSG: {e}").into_bytes()),
        }
    } else {
        ServerResponse::Other(cmd.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Авторизация команд
// ---------------------------------------------------------------------------

/// Байты, которые подписываются: `short(sessionId) | short(corrId) | short(entityId) | cmd`.
pub fn auth_bytes(
    session_id: &[u8],
    corr_id: &[u8],
    entity_id: &[u8],
    command: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = put_short(&mut out, session_id);
    let _ = put_short(&mut out, corr_id);
    let _ = put_short(&mut out, entity_id);
    out.extend_from_slice(command);
    out
}

/// Ed25519-подпись команды получателя.
pub fn sign_command(
    signing_key: &SigningKey,
    session_id: &[u8],
    corr_id: &[u8],
    entity_id: &[u8],
    command: &[u8],
) -> Vec<u8> {
    let bytes = auth_bytes(session_id, corr_id, entity_id, command);
    signing_key.sign(&bytes).to_bytes().to_vec()
}

/// Deniable-аутентификатор отправителя:
/// `crypto_box(sha512(authBytes), nonce=corrId, key=dh(serverPub, clientPriv))`.
///
/// Результат — 80 байт (64 + 16), как в `cbAuthenticate`.
pub fn deniable_authenticator(
    server_pub: &[u8; 32],
    client_secret: &StaticSecret,
    corr_id: &[u8; 24],
    auth_bytes: &[u8],
) -> Vec<u8> {
    let dh = client_secret.diffie_hellman(&X25519Public::from(*server_pub));
    let digest = Sha512::digest(auth_bytes);
    crypto_box_encrypt(dh.as_bytes(), corr_id, &digest)
}

/// Проверка Ed25519-подписи (для тестов и серверной стороны).
pub fn verify_command(
    verifying_key: &VerifyingKey,
    auth_bytes: &[u8],
    signature: &[u8],
) -> bool {
    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key.verify(auth_bytes, &sig).is_ok()
}

// ---------------------------------------------------------------------------
// Тело сообщения (client message envelope)
// ---------------------------------------------------------------------------

/// Зашифрованный конверт сообщения.
#[derive(Debug, Clone)]
pub struct ClientMsgEnvelope {
    /// Версия SMP-клиента (внутри заголовка).
    pub version: u16,
    /// Публичный X25519-ключ отправителя (только для confirmation).
    pub e2e_pub_x509: Option<Vec<u8>>,
    pub nonce: [u8; 24],
    pub enc_body: Vec<u8>,
}

/// Шифрует тело сообщения для отправки через очередь.
///
/// `dh_secret` — общий DH-секрет с получателем очереди;
/// `e2e_pub_x509` заполняется только для confirmation-сообщения.
pub fn encrypt_client_msg(
    dh_secret: &[u8; 32],
    version: u16,
    e2e_pub_x509: Option<&[u8]>,
    msg: &[u8],
) -> Result<Vec<u8>, SmpError> {
    use rand::RngCore;
    let padded_len = if e2e_pub_x509.is_some() {
        E2E_CONFIRMATION_LEN
    } else {
        E2E_MSG_LEN
    };
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let body = crypto_box_encrypt(dh_secret, &nonce, &pad(msg, padded_len)?);
    let mut out = Vec::with_capacity(2 + 1 + 24 + body.len());
    put_u16(&mut out, version);
    match e2e_pub_x509 {
        None => out.push(b'0'),
        Some(k) => {
            out.push(b'1');
            put_short(&mut out, k)?;
        }
    }
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Расшифровывает конверт сообщения (слой E2E между клиентами).
pub fn decrypt_client_msg(
    dh_secret: &[u8; 32],
    envelope: &[u8],
) -> Result<(ClientMsgEnvelope, Vec<u8>), SmpError> {
    if envelope.len() < 3 {
        return Err(SmpError::Eof);
    }
    let version = u16::from_be_bytes([envelope[0], envelope[1]]);
    let mut d = Decoder::new(&envelope[2..]);
    let e2e_pub_x509 = match d.u8()? {
        b'0' => None,
        b'1' => Some(d.short()?.to_vec()),
        other => {
            return Err(SmpError::InvalidTag {
                what: "e2ePubKey",
                got: other,
            })
        }
    };
    let nonce_bytes = d.take(24)?;
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(nonce_bytes);
    let enc_body = d.tail().to_vec();
    let plain = unpad(&crypto_box_decrypt(dh_secret, &nonce, &enc_body)?)?;
    Ok((
        ClientMsgEnvelope {
            version,
            e2e_pub_x509,
            nonce,
            enc_body,
        },
        plain,
    ))
}

/// Тело принятого сообщения после снятия серверного слоя шифрования.
#[derive(Debug, Clone)]
pub struct RcvMsgBody {
    /// Unix-время (секунды) на стороне сервера.
    pub timestamp: u64,
    /// Флаги сообщения (`T`/`F`).
    pub flags: u8,
    /// Конверт E2E-сообщения.
    pub envelope: Vec<u8>,
}

/// Расшифровывает `MSG` (серверный слой) и достаёт конверт.
pub fn decrypt_rcv_msg(
    server_dh_secret: &[u8; 32],
    msg_id: &[u8],
    body: &[u8],
) -> Result<RcvMsgBody, SmpError> {
    if msg_id.len() != 24 {
        return Err(SmpError::BadLength {
            expected: Some(24),
            got: msg_id.len(),
        });
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(msg_id);
    let plain = unpad(&crypto_box_decrypt(server_dh_secret, &nonce, body)?)?;
    if plain.len() < 10 {
        return Err(SmpError::Eof);
    }
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&plain[..8]);
    let timestamp = u64::from_be_bytes(ts);
    let flags = plain[8];
    if plain[9] != b' ' {
        return Err(SmpError::InvalidTag {
            what: "msgFlags",
            got: plain[9],
        });
    }
    Ok(RcvMsgBody {
        timestamp,
        flags,
        envelope: plain[10..].to_vec(),
    })
}

/// Заголовок приватной части сообщения (`PrivHeader`): `K <key>` или `_`.
pub fn encode_priv_header(sender_auth_x509: Option<&[u8]>) -> Result<Vec<u8>, SmpError> {
    let mut out = Vec::new();
    match sender_auth_x509 {
        None => out.push(b'_'),
        Some(k) => {
            out.push(b'K');
            put_short(&mut out, k)?;
        }
    }
    Ok(out)
}

/// Разбор приватного заголовка.
pub fn parse_priv_header(buf: &[u8]) -> Result<(Option<Vec<u8>>, &[u8]), SmpError> {
    if buf.is_empty() {
        return Err(SmpError::Eof);
    }
    match buf[0] {
        b'_' => Ok((None, &buf[1..])),
        b'K' => {
            let mut d = Decoder::new(&buf[1..]);
            let key = d.short()?.to_vec();
            Ok((Some(key), d.tail()))
        }
        other => Err(SmpError::InvalidTag {
            what: "PrivHeader",
            got: other,
        }),
    }
}

// ---------------------------------------------------------------------------
// Server handshake
// ---------------------------------------------------------------------------

/// Разобранный ответ сервера на handshake.
#[derive(Debug, Clone)]
pub struct ServerHelloInfo {
    pub min_version: u16,
    pub max_version: u16,
    pub session_id: Vec<u8>,
    /// DER сертификата цепочки (если сервер его прислал).
    pub cert_chain: Vec<u8>,
    /// DER подписанного объекта с сессионным ключом сервера.
    pub signed_object: Vec<u8>,
}

/// Разбирает server hello (после снятия паддинга блока).
///
/// Формат: `u16 minVersion | u16 maxVersion | short sessionId |
/// [short certChain | large signedObject]`.
pub fn parse_server_hello(block: &[u8]) -> Result<ServerHelloInfo, SmpError> {
    let mut d = Decoder::new(block);
    let min_version = d.u16()?;
    let max_version = d.u16()?;
    let session_id = d.short()?.to_vec();
    let (cert_chain, signed_object) = if d.remaining() == 0 {
        (Vec::new(), Vec::new())
    } else {
        // certChain = count(1) * [originalLength(u16) + x509]
        let count = d.u8()? as usize;
        let mut chain = vec![count as u8];
        for _ in 0..count {
            let len = d.u16()? as usize;
            chain.push((len >> 8) as u8);
            chain.push((len & 0xff) as u8);
            chain.extend_from_slice(d.take(len)?);
        }
        // signedRouterKey = originalLength(u16) + x509(Signed)
        let signed = if d.remaining() >= 2 {
            let mut dd = Decoder::new(d.tail());
            let s = dd.large()?.to_vec();
            s
        } else {
            Vec::new()
        };
        (chain, signed)
    };
    Ok(ServerHelloInfo {
        min_version,
        max_version,
        session_id,
        cert_chain,
        signed_object,
    })
}

/// Тип: (pubkey, candidates, signature) — pubkey X25519 сервера, возможные подписанные
/// байты (обёртка зависит от версии сервера), сама подпись.
pub type SignedPubkeyExtraction = ([u8; 32], Vec<Vec<u8>>, Vec<u8>);

/// Извлекает X25519-ключ сервера из DER подписанного объекта.
///
/// Возвращает `(pubkey, candidates, signature)`, где `candidates` — возможные
/// байты, которые сервер мог подписать (зависит от обёртки: OCTET STRING у
/// v7.0.x, голый SPKI SEQUENCE у публичных v7.1+).
pub fn extract_signed_pubkey(signed_der: &[u8]) -> Option<SignedPubkeyExtraction> {
    // SEQUENCE { signedObject, alg+signature }
    let (_, content, _) = der_tlv(signed_der)?;
    let (obj_tag, obj_content, rest) = der_tlv(content)?;
    // signedObject бывает OCTET STRING (0x04) либо явным SEQUENCE (0x30) с SPKI.
    if obj_tag != 0x04 && obj_tag != 0x30 {
        return None;
    }
    let signature = find_signature(rest, 0)?;
    let pubkey = parse_x25519_x509(obj_content)?;
    let hdr_len = content.len() - obj_content.len() - rest.len();
    let full_tlv = &content[..hdr_len + obj_content.len()];
    let mut candidates = vec![
        der_wrap_sequence(obj_content), // SEQUENCE(контент) — вариант v7.0.x
        full_tlv.to_vec(),              // голый TLV (SPKI) — вариант v7.1+
        der_wrap_sequence(full_tlv),    // SEQUENCE(TLV)
        obj_content.to_vec(),           // голый контент
    ];
    candidates.dedup();
    Some((pubkey, candidates, signature))
}

/// Оборачивает DER-объект в SEQUENCE (как `Start Sequence : ...` в Haskell).
fn der_wrap_sequence(inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(inner.len() + 4);
    out.push(0x30);
    let n = inner.len();
    if n < 128 {
        out.push(n as u8);
    } else {
        let mut bytes = Vec::new();
        let mut v = n;
        while v > 0 {
            bytes.push((v & 0xff) as u8);
            v >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(inner);
    out
}

/// Рекурсивно ищет BIT STRING (0x03) — подпись Ed25519 внутри DER.
fn find_signature(buf: &[u8], depth: u8) -> Option<Vec<u8>> {
    if depth > 5 {
        return None;
    }
    let mut rest = buf;
    while !rest.is_empty() {
        let (tag, content, r) = der_tlv(rest)?;
        match tag {
            0x03 => {
                if content.len() > 1 {
                    return Some(content[1..].to_vec());
                }
                return None;
            }
            0x04 | 0x30 => {
                if let Some(sig) = find_signature(content, depth + 1) {
                    return Some(sig);
                }
            }
            _ => {}
        }
        rest = r;
    }
    None
}

/// Разбор одного DER TLV: возвращает `(tag, content, остаток)`.
fn der_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    let first = buf[1];
    let (len, hdr) = if first & 0x80 == 0 {
        (first as usize, 2usize)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for b in &buf[2..2 + n] {
            len = (len << 8) | *b as usize;
        }
        (len, 2 + n)
    };
    if buf.len() < hdr + len {
        return None;
    }
    Some((tag, &buf[hdr..hdr + len], &buf[hdr + len..]))
}

/// Проверяет подпись сервера над его сессионным ключом.
///
/// `cert_der` — leaf-сертификат сервера (Ed25519).
pub fn verify_server_signed_key(
    cert_der: &[u8],
    signed_object_bytes: &[u8],
    signature: &[u8],
) -> bool {
    // Ed25519-сертификат (локальные/старые серверы) — через ed25519-dalek.
    if let Some(cert_key) = parse_ed25519_x509(cert_der) {
        let vk = match VerifyingKey::from_bytes(&cert_key) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig = match Signature::from_slice(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        return vk.verify(signed_object_bytes, &sig).is_ok();
    }
    // Ed448-сертификат (публичные релеи v7.1+) — через openssl (ed25519-dalek
    // Ed448 не поддерживает). Подпись Ed448 = 114 байт.
    if let Some(k) = parse_ed448_x509(cert_der) {
        let mut spki = ED448_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(&k);
        let pkey = match openssl::pkey::PKey::public_key_from_der(&spki) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let mut verifier = match openssl::sign::Verifier::new_without_digest(&pkey) {
            Ok(v) => v,
            Err(_) => return false,
        };
        return verifier
            .verify_oneshot(signature, signed_object_bytes)
            .unwrap_or(false);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::smp_wire::Decoder;

    #[test]
    fn spki_roundtrip() {
        let k = [7u8; 32];
        let der = x25519_x509(&k);
        assert_eq!(der.len(), 44);
        assert_eq!(parse_x25519_x509(&der), Some(k));
        let der2 = ed25519_x509(&k);
        assert_eq!(parse_ed25519_x509(&der2), Some(k));
    }

    #[test]
    fn padding_roundtrip() {
        for len in [0usize, 1, 100, 15900] {
            let msg = vec![0xAAu8; len];
            let p = pad(&msg, 16000).unwrap();
            assert_eq!(p.len(), 16000);
            assert_eq!(unpad(&p).unwrap(), msg);
        }
        assert!(pad(&vec![0u8; 15999], 16000).is_err());
    }

    #[test]
    fn secretbox_tag_first_layout() {
        let secret = [1u8; 32];
        let nonce = [2u8; 24];
        let msg = b"hello nexx";
        let ct = crypto_box_encrypt(&secret, &nonce, msg);
        assert_eq!(ct.len(), msg.len() + 16);
        // tag впереди: первые 16 байт — Poly1305-тег
        assert_ne!(&ct[..16], &[0u8; 16]);
        let pt = crypto_box_decrypt(&secret, &nonce, &ct).unwrap();
        assert_eq!(pt, msg);
        // неверный ключ -> ошибка
        assert!(crypto_box_decrypt(&[9u8; 32], &nonce, &ct).is_err());
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// KAT: наш `crypto_box_encrypt` должен побайтово совпадать с Haskell-эталоном
    /// simplexmq `cryptoBox` (Crypto.hs:1478), который валидирован против штатного
    /// вектора cryptonite `tests/XSalsa.hs` (vectorsCB) и равен libsodium `crypto_box`.
    /// Вектор ниже сгенерирован через `nacl.bindings.crypto_box(msg, nonce, pk, sk)`.
    #[test]
    fn crypto_box_kat_matches_simplexmq() {
        let sk: [u8; 32] = core::array::from_fn(|i| i as u8);
        let pk: [u8; 32] = unhex("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f")
            .try_into()
            .unwrap();
        let nonce: [u8; 24] = unhex("05101b26313c47525d68737e89949faab5c0cbd6e1ecf702")
            .try_into()
            .unwrap();
        let msg = unhex(
            "4e65585820696e7465726f70204b415420766563746f723a2063727970746f5f626f78206d757374206d61746368204861736b656c6c2073696d706c65786d712063727970746f426f78",
        );
        let expected = unhex(
            "63637da0a8921d5f6e52e9664bbfc2acfa872948cd258277282e39df81b45a899337366d5520a1d3111c427de010479308ce26b46877b1507477653a5db2702d9522c0ca9768f6b5e1d8f3e96f7e3fe96e7b4be295c05df5bf4d",
        );
        let dh = StaticSecret::from(sk).diffie_hellman(&X25519Public::from(pk));
        let ct = crypto_box_encrypt(dh.as_bytes(), &nonce, &msg);
        assert_eq!(ct, expected, "crypto_box не совпал с Haskell-эталоном simplexmq");
        assert_eq!(crypto_box_decrypt(dh.as_bytes(), &nonce, &ct).unwrap(), msg);
    }

    #[test]
    fn new_command_layout_v17() {
        let cmd = cmd_new(
            17,
            &[1u8; 44],
            &[2u8; 44],
            None,
            true,
            None,
            None,
        )
        .unwrap();
        assert_eq!(&cmd[..4], b"NEW ");
        let mut d = Decoder::new(&cmd[4..]);
        assert_eq!(d.short().unwrap().len(), 44);
        assert_eq!(d.short().unwrap().len(), 44);
        assert_eq!(d.u8().unwrap(), b'0'); // basic auth
        assert_eq!(d.u8().unwrap(), b'S'); // subscribe
        assert_eq!(d.u8().unwrap(), b'0'); // queue req data
        assert_eq!(d.u8().unwrap(), b'0'); // ntf creds
        assert!(d.is_empty());
    }

    #[test]
    fn ack_and_send_layout() {
        let ack = cmd_ack(&[3u8; 24]).unwrap();
        assert_eq!(&ack[..4], b"ACK ");
        let mut d = Decoder::new(&ack[4..]);
        assert_eq!(d.short().unwrap().len(), 24);

        let env = vec![0xAAu8; 100];
        let send = cmd_send(true, &env);
        assert_eq!(&send[..5], b"SEND ");
        assert_eq!(send[5], b'T');
        assert_eq!(send[6], b' ');
        assert_eq!(&send[7..], &env[..]);
    }

    #[test]
    fn ids_parse_roundtrip() {
        let mut cmd = Vec::new();
        cmd.extend_from_slice(b"IDS ");
        cmd.push(24);
        cmd.extend_from_slice(&[1u8; 24]);
        cmd.push(24);
        cmd.extend_from_slice(&[2u8; 24]);
        cmd.push(44);
        cmd.extend_from_slice(&x25519_x509(&[3u8; 32]));
        let ids = parse_ids(17, &cmd).unwrap();
        assert_eq!(ids.rcv_id, vec![1u8; 24]);
        assert_eq!(ids.snd_id, vec![2u8; 24]);
        assert_eq!(parse_x25519_x509(&ids.srv_dh_x509), Some([3u8; 32]));
    }

    #[test]
    fn envelope_roundtrip() {
        let secret = [5u8; 32];
        let env = encrypt_client_msg(&secret, 20, None, b"payload").unwrap();
        let (hdr, plain) = decrypt_client_msg(&secret, &env).unwrap();
        assert_eq!(hdr.version, 20);
        assert!(hdr.e2e_pub_x509.is_none());
        assert_eq!(plain, b"payload".to_vec());
    }

    #[test]
    fn confirmation_envelope_has_key() {
        let secret = [6u8; 32];
        let key = x25519_x509(&[8u8; 32]);
        let env = encrypt_client_msg(&secret, 20, Some(&key), b"conf").unwrap();
        let (hdr, plain) = decrypt_client_msg(&secret, &env).unwrap();
        assert_eq!(hdr.e2e_pub_x509.unwrap(), key);
        assert_eq!(plain, b"conf".to_vec());
    }

    #[test]
    fn rcv_msg_layer() {
        let server_secret = [4u8; 32];
        let msg_id = [9u8; 24];
        let envelope = encrypt_client_msg(&[1u8; 32], 20, None, b"hi").unwrap();
        let mut rcv = Vec::new();
        rcv.extend_from_slice(&1234567890u64.to_be_bytes());
        rcv.push(b'F');
        rcv.push(b' ');
        rcv.extend_from_slice(&envelope);
        // сервер паддит тело до MaxRcvMessageLen + 2 = 16106 (simplexmq Protocol.hs)
        let body = crypto_box_encrypt(&server_secret, &msg_id, &pad(&rcv, 16106).unwrap());
        let parsed = decrypt_rcv_msg(&server_secret, &msg_id, &body).unwrap();
        assert_eq!(parsed.timestamp, 1234567890);
        assert_eq!(parsed.flags, b'F');
        assert_eq!(parsed.envelope, envelope);
    }

    #[test]
    fn signature_and_deniable_auth() {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let cmd = cmd_sub();
        let sig = sign_command(&sk, &[1u8; 32], &[2u8; 24], &[3u8; 24], &cmd);
        let bytes = auth_bytes(&[1u8; 32], &[2u8; 24], &[3u8; 24], &cmd);
        assert!(verify_command(&sk.verifying_key(), &bytes, &sig));

        let secret = StaticSecret::from([12u8; 32]);
        let server_pub = X25519Public::from([13u8; 32]);
        let auth = deniable_authenticator(server_pub.as_bytes(), &secret, &[14u8; 24], &bytes);
        assert_eq!(auth.len(), 80);
    }

    #[test]
    fn block_chain_is_deterministic() {
        let mut a = SbChainKey::init(b"sess", &[1u8; 32]).1;
        let mut b = SbChainKey::init(b"sess", &[1u8; 32]).1;
        let (k1, n1) = a.next();
        let (k2, n2) = b.next();
        assert_eq!(k1, k2);
        assert_eq!(n1, n2);
        assert_ne!(k1, [0u8; 32]);
    }
}
