//! SMP-клиент: TLS-транспорт, handshake, шифрование блоков, обмен командами.
//!
//! Реализация по эталону `simplexmq` (~/xftp-research/simplexmq):
//! * TLS 1.3 с ALPN `smp/1`;
//! * **сервер первым** шлёт свой handshake (server hello), затем клиент шлёт свой;
//! * `sessionId` берём из server hello (это tls-unique клиента, который сервер
//!   уже проверил у себя) — так подписи и HKDF-соль совпадают байт-в-байт;
//! * сессионный X25519-ключ сервера лежит в подписанном объекте из цепочки
//!   сертификатов; подпись проверяется по leaf-сертификату;
//! * с v11 транспортные блоки шифруются secretbox по цепочке ключей.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::crypto::sha256_raw;
use crate::protocols::smp::{
    auth_bytes, cmd_ack, cmd_new, cmd_send, cmd_sub, crypto_box_decrypt, crypto_box_encrypt,
    decrypt_client_msg, decrypt_rcv_msg, deniable_authenticator, ed25519_x509, encrypt_client_msg,
    extract_signed_pubkey, pad, parse_response, parse_server_hello, sign_command, unpad,
    verify_server_signed_key, x25519_x509, QueueIds, RecipientKeys, SbChainKey, ServerResponse,
};
use crate::protocols::smp_wire::{
    decode_batch, decode_block, decode_transmission_v, encode_batch, encode_client_hello,
    encode_block, encode_transmission_v, new_corr_id, put_short, ClientHello, Transmission,
    BLOCK_SIZE,
};

/// Максимальная версия протокола, которую поддерживает клиент.
pub const CLIENT_MAX_VERSION: u16 = 20;

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// Абстракция TLS-потока: позволяет выбирать бэкенд (rustls для локальных
/// серверов, openssl — для публичных релеев, см. connect_openssl_with_ca).
pub trait TlsIo: Send {
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()>;
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()>;
    fn flush(&mut self) -> std::io::Result<()>;
    /// Тайм-аут чтения нижележащего TCP-сокета. Нужен неблокирующему poll:
    /// без него read_exact блокируется до 60 с (дефолтный тайм-аут подключения),
    /// и команды из UI ждут в очереди. По умолчанию — ничего не делает.
    fn set_read_timeout(&mut self, _d: Option<Duration>) {}
}

impl TlsIo for TlsStream {
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        Read::read_exact(self, buf)
    }
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        Write::write_all(self, buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Write::flush(self)
    }
    fn set_read_timeout(&mut self, d: Option<Duration>) {
        let _ = self.get_mut().set_read_timeout(d);
    }
}

impl TlsIo for Box<dyn TlsIo> {
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        (**self).read_exact(buf)
    }
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        (**self).write_all(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        (**self).flush()
    }
    fn set_read_timeout(&mut self, d: Option<Duration>) {
        (**self).set_read_timeout(d)
    }
}

/// TLS-поток на openssl. Нужен для публичных релеев SimpleX: их hs-tls на порту
/// 5223 требует ed448 в signature_algorithms ClientHello (ring его не умеет),
/// а при v7.1+ sessionId = TLS Finished, который rustls не отдаёт наружу.
pub struct OpensslStream {
    pub inner: openssl::ssl::SslStream<TcpStream>,
}

impl TlsIo for OpensslStream {
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        Read::read_exact(&mut self.inner, buf)
    }
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        Write::write_all(&mut self.inner, buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Write::flush(&mut self.inner)
    }
    fn set_read_timeout(&mut self, d: Option<Duration>) {
        let _ = self.inner.get_mut().set_read_timeout(d);
    }
}

/// Ошибка транспорта.
pub type SmpResult<T> = Result<T, String>;

fn err<T>(msg: impl Into<String>) -> SmpResult<T> {
    Err(msg.into())
}

/// TLS-поток с блокирующим чтением/записью.
fn tls_write_all(stream: &mut dyn TlsIo, buf: &[u8]) -> SmpResult<()> {
    stream
        .write_all(buf)
        .map_err(|e| format!("TLS write: {e}"))?;
    stream.flush().map_err(|e| format!("TLS flush: {e}"))
}

fn tls_read_exact(stream: &mut dyn TlsIo, buf: &mut [u8]) -> SmpResult<()> {
    stream.read_exact(buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            "TLS: соединение закрыто при чтении".to_string()
        } else {
            format!("TLS read: {e}")
        }
    })
}

/// Разбирает PEM с сертификатами (без внешних зависимостей).
pub fn parse_pem_certs(pem: &str) -> SmpResult<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = &rest[start + "-----BEGIN CERTIFICATE-----".len()..];
        let end = after
            .find("-----END CERTIFICATE-----")
            .ok_or_else(|| "PEM: не найден END CERTIFICATE".to_string())?;
        let b64: String = after[..end].chars().filter(|c| !c.is_whitespace()).collect();
        let der = crate::crypto::base64_decode(&b64).map_err(|e| format!("PEM: base64: {e}"))?;
        out.push(der);
        rest = &after[end + "-----END CERTIFICATE-----".len()..];
    }
    Ok(out)
}

/// Разбирает цепочку сертификатов SimpleX: `count(1) * [u16 len + DER]`.
pub fn split_cert_chain(blob: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if blob.is_empty() {
        return out;
    }
    let count = blob[0] as usize;
    let mut p = 1usize;
    for _ in 0..count {
        if p + 2 > blob.len() {
            break;
        }
        let len = u16::from_be_bytes([blob[p], blob[p + 1]]) as usize;
        p += 2;
        if p + len > blob.len() {
            break;
        }
        out.push(blob[p..p + len].to_vec());
        p += len;
    }
    out
}

/// Верификатор сертификата сервера в режиме **пиннинга отпечатка**.
///
/// Сертификаты SimpleX (CA `CN=SMP server CA, O=SimpleX`) выпускаются **без SAN** —
/// строгий webpki/rustls их отвергает («certificate is not valid for any names»).
/// В модели SimpleX идентичность сервера определяется не именем хоста, а
/// отпечатком его CA (keyHash из адреса `smp://keyHash@host:port`), поэтому здесь:
/// 1) принимается цепочка, содержащая сертификат с ожидаемым SHA-256;
/// 2) иначе — принимается сертификат, чей CN совпадает с ожидаемым хостом.
#[derive(Debug)]
struct PinnedCertVerifier {
    /// Ожидаемые SHA-256 отпечатки сертификатов (CA).
    expected_fps: Vec<[u8; 32]>,
    /// Ожидаемый CN (если пиннинг по отпечатку не сработал).
    expected_cn: Option<String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut chain: Vec<&[u8]> = vec![end_entity.as_ref()];
        for i in intermediates {
            chain.push(i.as_ref());
        }
        for der in &chain {
            let fp = sha256_raw(der);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&fp);
            if self.expected_fps.contains(&arr) {
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
        }
        // Запасной путь: CN сертификата == ожидаемый хост (SimpleX-сертификаты без SAN).
        if let Some(cn) = &self.expected_cn {
            for der in &chain {
                if let Ok(certs) = parse_pem_certs(&der_to_pem(der)) {
                    for c in certs {
                        let _ = c;
                    }
                }
            }
            if cert_cn_matches(end_entity.as_ref(), cn) {
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
        }
        Err(rustls::Error::General(
            "отпечаток сертификата сервера не совпал с ожидаемым (keyHash)".to_string(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Достаёт CN из DER-сертификата (минимальный разбор X.509).
fn cert_cn_matches(der: &[u8], cn: &str) -> bool {
    // Ищем ASCII-строку CN в printable-части сертификата.
    let text: String = der.iter().filter(|b| (32..127).contains(*b)).map(|b| *b as char).collect();
    text.contains(&format!("CN={cn}")) || text.contains(&format!("CN = {cn}"))
}

/// Оборачивает DER в PEM (для совместимости с парсером).
fn der_to_pem(der: &[u8]) -> String {
    let b64 = crate::crypto::base64url_encode(der);
    format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")
}

/// Адрес SMP-сервера.
#[derive(Debug, Clone)]
pub struct SmpAddress {
    pub host: String,
    pub port: u16,
    /// keyHash из адреса (`smp://keyHash@host:port`) — None для прямого подключения.
    pub key_hash: Option<String>,
}

impl SmpAddress {
    /// Разбирает `smp://keyHash@host:port`, `host:port` или `host`.
    pub fn parse(addr: &str) -> SmpResult<Self> {
        let mut s = addr.trim();
        let mut key_hash = None;
        if let Some(rest) = s.strip_prefix("smp://") {
            s = rest;
        }
        if let Some(rest) = s.strip_prefix("https://") {
            s = rest;
        }
        if let Some((hash, rest)) = s.split_once('@') {
            key_hash = Some(hash.to_string());
            s = rest;
        }
        let s = s.split('/').next().unwrap_or(s);
        let (host, port) = match s.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>().map_err(|_| format!("неверный порт в адресе: {addr}"))?,
            ),
            None => (s.to_string(), 443),
        };
        if host.is_empty() {
            return err(format!("пустой хост в адресе: {addr}"));
        }
        Ok(SmpAddress {
            host,
            port,
            key_hash,
        })
    }
}

/// Тип порции transmissions: (authenticator, corrId, entityId, command).
pub type TransmissionItem = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Живая сессия SMP-сервера.
pub struct SmpClient {
    stream: Box<dyn TlsIo>,
    /// Согласованная версия протокола.
    pub version: u16,
    /// sessionId из server hello (tls-unique клиента).
    pub session_id: Vec<u8>,
    /// Сессионный X25519-ключ сервера (из подписанного объекта цепочки).
    pub server_session_pub: Option<[u8; 32]>,
    /// DER leaf-сертификата сервера.
    pub cert_der: Vec<u8>,
    /// SHA-256 от leaf-сертификата.
    pub key_hash: Vec<u8>,
    /// Отпечаток CA-сертификата сервера из SMP-цепочки (настоящий keyHash SimpleX).
    pub smp_ca_fingerprint: Option<Vec<u8>>,
    /// Сообщения, пришедшие не по запросу (уведомления очереди).
    pub pending: Vec<Vec<u8>>,
    client_dh: StaticSecret,
    snd_chain: Option<SbChainKey>,
    rcv_chain: Option<SbChainKey>,
    /// Секрет сессии (DH) — для диагностики и пересчёта цепочек.
    pub session_secret: Option<[u8; 32]>,
}

impl SmpClient {
    /// Подключается к SMP-серверу и выполняет handshake.
    pub fn connect(host: &str, port: u16) -> SmpResult<Self> {
        SmpClient::connect_with_ca(host, port, None)
    }

    /// Подключается к SMP-серверу с **пиннингом CA** (модель SimpleX: сервер
    /// идентифицируется отпечатком своего CA-сертификата, а не публичным CA).
    ///
    /// `ca_pem` — PEM с CA-сертификатом сервера; если None — системные/public CA.
    pub fn connect_with_ca(host: &str, port: u16, ca_pem: Option<&str>) -> SmpResult<Self> {
        let mut roots = RootCertStore::empty();
        let mut pinned_ca: Option<Vec<u8>> = None;
        let mut ca_fps: Option<Vec<[u8; 32]>> = None;
        match ca_pem {
            Some(pem) => {
                let certs = parse_pem_certs(pem)?;
                if certs.is_empty() {
                    return err("в PEM не найдено ни одного сертификата");
                }
                let mut fps = Vec::with_capacity(certs.len());
                for der in &certs {
                    roots
                        .add(rustls::pki_types::CertificateDer::from(der.clone()))
                        .map_err(|e| format!("CA не принят: {e}"))?;
                    let fp = sha256_raw(der);
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&fp);
                    fps.push(arr);
                }
                pinned_ca = certs.last().cloned();
                ca_fps = Some(fps);
            }
            None => {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = match &ca_fps {
            Some(fps) => {
                // Пиннинг по отпечатку CA: сертификаты SimpleX идут без SAN.
                let verifier = PinnedCertVerifier {
                    expected_fps: fps.clone(),
                    expected_cn: Some(host.to_string()),
                    provider: provider.clone(),
                };
                ClientConfig::builder_with_provider(provider.clone())
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(|e| format!("rustls config: {e}"))?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_no_client_auth()
            }
            None => ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| format!("rustls config: {e}"))?
                .with_root_certificates(roots)
                .with_no_client_auth(),
        };
        config.alpn_protocols = vec![b"smp/1".to_vec()];

        let sni = ServerName::try_from(host.to_string()).map_err(|e| format!("SNI: {e}"))?;
        let conn =
            ClientConnection::new(Arc::new(config), sni).map_err(|e| format!("TLS init: {e}"))?;
        let sock = TcpStream::connect((host, port)).map_err(|e| format!("TCP connect {host}:{port}: {e}"))?;
        sock.set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| format!("read timeout: {e}"))?;
        sock.set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("write timeout: {e}"))?;
        let mut stream = StreamOwned::new(conn, sock);
        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(|e| format!("TLS handshake: {e}"))?;
        }
        let certs = stream
            .conn
            .peer_certificates()
            .ok_or_else(|| "TLS: нет сертификата сервера".to_string())?;
        let cert_der = certs[0].as_ref().to_vec();
        // Отпечаток (keyHash) — это отпечаток CA-сертификата сервера:
        // последний в цепочке, либо сам leaf (когда сертификат самоподписанный).
        let key_hash = match pinned_ca {
            Some(ca) => sha256_raw(&ca),
            None => sha256_raw(certs.last().map(|c| c.as_ref()).unwrap_or(&cert_der)),
        };

        let mut client = SmpClient {
            stream: Box::new(stream),
            version: 0,
            session_id: Vec::new(),
            server_session_pub: None,
            cert_der,
            key_hash,
            smp_ca_fingerprint: None,
            pending: Vec::new(),
            client_dh: StaticSecret::random_from_rng(rand::rngs::OsRng),
            snd_chain: None,
            rcv_chain: None,
            session_secret: None,
        };
        client.smp_handshake()?;
        Ok(client)
    }

    /// Подключение через **openssl** — для публичных релеев SimpleX (порт 5223).
    ///
    /// Их hs-tls требует в ClientHello TLS1.3 + CHACHA20_POLY1305 + X25519 +
    /// **ed448** в signature_algorithms (проверено pcap-диффом: без ed448 —
    /// alert 40). rustls/ring ed448 не поддерживает, поэтому rustls-бэкенд к
    /// публичным релеям не подключается. Пиннинг — вручную по SHA-256
    /// сертификатов цепочки (как в PinnedCertVerifier); реальная идентичность
    /// сервера дополнительно сверяется по keyHash из SMP server hello.
    pub fn connect_openssl_with_ca(host: &str, port: u16, ca_pem: Option<&str>) -> SmpResult<Self> {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

        let mut builder =
            SslConnector::builder(SslMethod::tls()).map_err(|e| format!("openssl ctx: {e}"))?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| format!("openssl min ver: {e}"))?;
        builder
            .set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256")
            .map_err(|e| format!("openssl ciphersuites: {e}"))?;
        // ed448 обязателен для публичных релеев; дальше — стандартный набор.
        builder
            .set_sigalgs_list(
                "ed448:ed25519:ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512",
            )
            .map_err(|e| format!("openssl sigalgs: {e}"))?;
        builder
            .set_groups_list("X25519")
            .map_err(|e| format!("openssl groups: {e}"))?;
        builder
            .set_alpn_protos(b"\x05smp/1")
            .map_err(|e| format!("openssl alpn: {e}"))?;
        // Сертификаты проверяем вручную по отпечаткам (SimpleX CA — приватный).
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();

        let ca_fps: Option<Vec<[u8; 32]>> = match ca_pem {
            Some(pem) => {
                let certs = parse_pem_certs(pem)?;
                if certs.is_empty() {
                    return err("в PEM не найдено ни одного сертификата");
                }
                Some(
                    certs
                        .iter()
                        .map(|der| {
                            let fp = sha256_raw(der);
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&fp);
                            arr
                        })
                        .collect(),
                )
            }
            None => None,
        };

        let sock =
            TcpStream::connect((host, port)).map_err(|e| format!("TCP connect {host}:{port}: {e}"))?;
        sock.set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| format!("read timeout: {e}"))?;
        sock.set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("write timeout: {e}"))?;
        // connect() ставит SNI = host и завершает handshake.
        let stream = OpensslStream {
            inner: connector
                .connect(host, sock)
                .map_err(|e| format!("TLS handshake: {e}"))?,
        };

        // Ручной пиннинг: хотя бы один сертификат цепочки должен совпасть по SHA-256.
        let chain = stream
            .inner
            .ssl()
            .peer_cert_chain()
            .ok_or_else(|| "TLS: нет цепочки сертификатов сервера".to_string())?;
        let ders: Vec<Vec<u8>> = chain
            .iter()
            .map(|c| c.to_der().map_err(|e| format!("cert der: {e}")))
            .collect::<Result<_, _>>()?;
        let cert_der = ders.first().cloned().unwrap_or_default();
        if let Some(fps) = &ca_fps {
            let ok = ders.iter().any(|der| {
                let fp = sha256_raw(der);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&fp);
                fps.contains(&arr)
            });
            if !ok {
                return err("TLS: отпечаток цепочки не совпадает с пинованным CA");
            }
        }
        let key_hash = match &ca_fps {
            Some(fps) => fps
                .last()
                .map(|a| a.to_vec())
                .unwrap_or_else(|| sha256_raw(ders.last().unwrap_or(&cert_der))),
            None => sha256_raw(ders.last().unwrap_or(&cert_der)),
        };

        let mut client = SmpClient {
            stream: Box::new(stream),
            version: 0,
            session_id: Vec::new(),
            server_session_pub: None,
            cert_der,
            key_hash,
            smp_ca_fingerprint: None,
            pending: Vec::new(),
            client_dh: StaticSecret::random_from_rng(rand::rngs::OsRng),
            snd_chain: None,
            rcv_chain: None,
            session_secret: None,
        };
        client.smp_handshake()?;
        Ok(client)
    }

    /// Подключение по SMP-адресу (`smp://keyHash@host:port`).
    pub fn connect_addr(addr: &str) -> SmpResult<Self> {
        let a = SmpAddress::parse(addr)?;
        let client = SmpClient::connect(&a.host, a.port)?;
        if let Some(expected) = &a.key_hash {
            if let Ok(exp) = crate::crypto::base64url_decode(expected) {
                let exp_hex = crate::crypto::hex_encode(&exp);
                let got_hex = crate::crypto::hex_encode(&client.key_hash);
                if exp_hex != got_hex {
                    return err(format!(
                        "keyHash сервера не совпадает: ожидался {expected}, получен {got_hex}"
                    ));
                }
            }
        }
        Ok(client)
    }

    /// SMP-handshake: читаем server hello, шлём client hello, считаем ключи.
    fn smp_handshake(&mut self) -> SmpResult<()> {
        // 1. Сервер присылает свой handshake первым.
        let mut block = vec![0u8; BLOCK_SIZE];
        tls_read_exact(&mut self.stream, &mut block)?;
        let hello_bytes = decode_block(&block).map_err(|e| format!("server hello block: {e}"))?;
        let hello = parse_server_hello(&hello_bytes).map_err(|e| format!("server hello: {e}"))?;

        if hello.min_version > CLIENT_MAX_VERSION {
            return err(format!(
                "сервер требует минимум v{}, клиент поддерживает максимум v{}",
                hello.min_version, CLIENT_MAX_VERSION
            ));
        }
        let version = CLIENT_MAX_VERSION.min(hello.max_version);
        self.version = version;
        self.session_id = hello.session_id.clone();

        // 2. Идентичность сервера: отпечаток CA-сертификата из SMP-цепочки
        //    (это и есть keyHash из адреса smp://keyHash@host:port).
        let certs = split_cert_chain(&hello.cert_chain);
        let ca_der = certs
            .last()
            .ok_or_else(|| "сервер не прислал цепочку сертификатов".to_string())?;
        let ca_fp = sha256_raw(ca_der);
        self.smp_ca_fingerprint = Some(ca_fp.clone());
        self.key_hash = ca_fp.clone();

        // 3. Клиентский handshake.
        let client_pub = X25519Public::from(&self.client_dh);
        let client_pub_x509 = x25519_x509(client_pub.as_bytes());
        let hello_out = encode_client_hello(&ClientHello {
            version,
            key_hash: &ca_fp,
            auth_pub_key: Some(&client_pub_x509),
            proxy_server: false,
            client_service: None,
        })
        .map_err(|e| format!("client hello: {e}"))?;
        let block = encode_block(&hello_out).map_err(|e| format!("client hello block: {e}"))?;
        tls_write_all(&mut self.stream, &block)?;

        // 4. Сессионный ключ сервера + общий секрет.
        if hello.signed_object.is_empty() {
            return err("сервер не прислал сессионный ключ (v<7 или нет сертификата)");
        }
        let (server_pub, signed_candidates, signature) = extract_signed_pubkey(&hello.signed_object)
            .ok_or_else(|| "не удалось извлечь сессионный ключ сервера".to_string())?;
        // Подписанные байты зависят от обёртки объекта у сервера:
        // v7.0.x шлёт OCTET STRING-обёртку, публичные v7.1+ — голый SPKI SEQUENCE.
        // Пробуем все канонические варианты (ср. `Start Sequence : ...` в Haskell).
        if !signed_candidates
            .iter()
            .any(|c| verify_server_signed_key(&self.cert_der, c, &signature))
        {
            return err("подпись сессионного ключа сервера не прошла проверку");
        }
        self.server_session_pub = Some(server_pub);

        // 4. Секрет сессии и цепочка ключей блоков (v11+).
        let dh = self
            .client_dh
            .diffie_hellman(&X25519Public::from(server_pub));
        if version >= crate::protocols::smp::ENCRYPTED_BLOCK_VERSION {
            let (ck1, ck2) = SbChainKey::init(&self.session_id, dh.as_bytes());
            // клиент шлёт ck2, получает ck1 (в simplexmq — swap для клиента)
            self.snd_chain = Some(ck2);
            self.rcv_chain = Some(ck1);
        }
        self.session_secret = Some(*dh.as_bytes());
        Ok(())
    }

    /// Отправляет блок (с шифрованием, если версия >= 11).
    fn write_block(&mut self, content: &[u8]) -> SmpResult<()> {
        let block = match self.snd_chain.as_mut() {
            Some(chain) => {
                let (sk, nonce) = chain.next();
                let padded = pad(content, BLOCK_SIZE - 16).map_err(|e| format!("pad block: {e}"))?;
                crypto_box_encrypt(&sk, &nonce, &padded)
            }
            None => encode_block(content).map_err(|e| format!("encode block: {e}"))?,
        };
        tls_write_all(&mut self.stream, &block)
    }

    /// Читает блок (с расшифровкой, если версия >= 11).
    fn read_block(&mut self) -> SmpResult<Vec<u8>> {
        let mut block = vec![0u8; BLOCK_SIZE];
        tls_read_exact(&mut self.stream, &mut block)?;
        match self.rcv_chain.as_mut() {
            Some(chain) => {
                let (sk, nonce) = chain.next();
                let plain = match crypto_box_decrypt(&sk, &nonce, &block) {
                    Ok(p) => p,
                    Err(e) => {
                        // Диагностика: перебираем варианты цепочки/соли, чтобы найти расхождение.
                        let mut report = format!("decrypt block: {e}");
                        if let Some(secret) = self.session_secret {
                            let cands: Vec<(String, SbChainKey)> = vec![
                                ("ck1#1".into(), SbChainKey::init(&self.session_id, &secret).0),
                                ("ck1#2".into(), SbChainKey::init(&self.session_id, &secret).0),
                                ("ck2#1".into(), SbChainKey::init(&self.session_id, &secret).1),
                                ("ck2#2".into(), SbChainKey::init(&self.session_id, &secret).1),
                                ("nosalt1#1".into(), SbChainKey::init(&[], &secret).0),
                                ("nosalt2#1".into(), SbChainKey::init(&[], &secret).1),
                            ];
                            for (label, mut chain) in cands {
                                let rounds = if label.ends_with("#2") { 2 } else { 1 };
                                for _ in 0..rounds {
                                    let (sk, nonce) = chain.next();
                                    if crypto_box_decrypt(&sk, &nonce, &block).is_ok() {
                                        report.push_str(&format!("; WORKS={label}"));
                                        break;
                                    }
                                }
                            }
                            {
                                let (sk1, n1) = SbChainKey::init(&self.session_id, &secret).0.next();
                                let (sk2, n2) = SbChainKey::init(&self.session_id, &secret).1.next();
                                report.push_str(&format!(
                                    "; ck1.next sk={} nonce={}; ck2.next sk={} nonce={}",
                                    crate::crypto::hex_encode(&sk1),
                                    crate::crypto::hex_encode(&n1),
                                    crate::crypto::hex_encode(&sk2),
                                    crate::crypto::hex_encode(&n2)
                                ));
                            }
                            report.push_str(&format!(
                                "; block[0..64]={}",
                                crate::crypto::hex_encode(&block[..64])
                            ));
                            report.push_str(&format!(
                                "; sessId={} secret={}",
                                crate::crypto::hex_encode(&self.session_id),
                                crate::crypto::hex_encode(&secret)
                            ));
                        }
                        return err(report);
                    }
                };
                unpad(&plain).map_err(|e| format!("unpad block: {e}"))
            }
            None => decode_block(&block).map_err(|e| format!("decode block: {e}")),
        }
    }

    /// Отправляет transmission (команду) и возвращает corrId.
    pub fn send_command(
        &mut self,
        authenticator: &[u8],
        entity_id: &[u8],
        command: &[u8],
    ) -> SmpResult<Vec<u8>> {
        let corr_id = new_corr_id();
        let t = Transmission {
            authenticator,
            corr_id: &corr_id,
            entity_id,
            command,
        };
        let encoded = encode_transmission_v(self.version, &t).map_err(|e| format!("encode transmission: {e}"))?;
        let batch = encode_batch(&[encoded]).map_err(|e| format!("encode batch: {e}"))?;
        self.write_block(&batch)?;
        Ok(corr_id)
    }

    /// Устанавливает тайм-аут чтения сокета. Для неблокирующего poll ставьте
    /// малое значение (напр. 300 мс): read_exact тогда возвращает
    /// WouldBlock/"Resource temporarily unavailable" вместо блокировки до 60 с.
    pub fn set_read_timeout(&mut self, d: Option<Duration>) {
        self.stream.set_read_timeout(d);
    }

    /// Тип порции transmissions: (authenticator, corrId, entityId, command).
    pub fn recv_transmissions(&mut self) -> SmpResult<Vec<TransmissionItem>> {
        let batch = self.read_block()?;
        let items = decode_batch(&batch).map_err(|e| format!("decode batch: {e}"))?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let t = decode_transmission_v(self.version, &item).map_err(|e| format!("decode transmission: {e}"))?;
            out.push((
                t.authenticator.to_vec(),
                t.corr_id.to_vec(),
                t.entity_id.to_vec(),
                t.command.to_vec(),
            ));
        }
        Ok(out)
    }

    /// Ждёт ответа на конкретную команду (по corrId).
    pub fn wait_response(&mut self, corr_id: &[u8]) -> SmpResult<ServerResponse> {
        for _ in 0..64 {
            let items = self.recv_transmissions()?;
            for (auth, corr, entity, cmd) in items {
                if corr.is_empty() {
                    // Уведомление сервера (например, сообщение очереди).
                    // MSG может прийти в том же batch, что и ответ на нашу команду
                    // (например, на ACK) — складываем в pending, заберём позже.
                    if cmd.starts_with(b"MSG ") {
                        self.pending.push(cmd);
                    }
                    continue;
                }
                if corr == corr_id {
                    let _ = (auth, entity);
                    return Ok(parse_response(self.version, &cmd));
                }
            }
        }
        err("не дождались ответа сервера")
    }

    /// `PING` — проверка живости соединения.
    pub fn ping(&mut self) -> SmpResult<()> {
        let corr_id = new_corr_id();
        let mut cmd = Vec::new();
        cmd.extend_from_slice(b"PING");
        let t = Transmission {
            authenticator: b"",
            corr_id: &corr_id,
            entity_id: b"",
            command: &cmd,
        };
        let encoded = encode_transmission_v(self.version, &t).map_err(|e| format!("encode ping: {e}"))?;
        let batch = encode_batch(&[encoded]).map_err(|e| format!("encode batch: {e}"))?;
        self.write_block(&batch)?;
        match self.wait_response(&corr_id)? {
            ServerResponse::Pong => Ok(()),
            other => err(format!("ожидался PONG, получено {other:?}")),
        }
    }

    /// Создаёт очередь (`NEW`) и возвращает её идентификаторы.
    pub fn create_queue(&mut self, keys: &RecipientKeys) -> SmpResult<QueueIds> {
        let auth_pub = ed25519_x509(keys.auth_signing.verifying_key().as_bytes());
        let dh_pub = x25519_x509(X25519Public::from(&keys.dh_secret).as_bytes());
        let cmd = cmd_new(self.version, &auth_pub, &dh_pub, None, true, None, None)
            .map_err(|e| format!("cmd NEW: {e}"))?;
        // NEW авторизуется ключом получателя; entityId пустой.
        // corrId в подписи и в transmission должен совпадать — считаем один раз.
        let corr_id = new_corr_id();
        let auth = sign_command(&keys.auth_signing, &self.session_id, &corr_id, b"", &cmd);
        let t = Transmission {
            authenticator: &auth,
            corr_id: &corr_id,
            entity_id: b"",
            command: &cmd,
        };
        let encoded = encode_transmission_v(self.version, &t).map_err(|e| format!("encode transmission: {e}"))?;
        let batch = encode_batch(&[encoded]).map_err(|e| format!("encode batch: {e}"))?;
        self.write_block(&batch)?;
        match self.wait_response(&corr_id)? {
            ServerResponse::Ids(ids) => Ok(ids),
            ServerResponse::Err(e) => err(format!("сервер отверг NEW: {e}")),
            other => err(format!("неожиданный ответ на NEW: {other:?}")),
        }
    }

    /// Отправляет сообщение в очередь (`SEND`).
    ///
    /// `sender_secret` — DH-секрет с получателем очереди; при `confirmation`
    /// в заголовок добавляется публичный X25519-ключ отправителя.
    pub fn send_message(
        &mut self,
        snd_id: &[u8],
        sender_secret: &[u8; 32],
        sender_pub_x509: Option<&[u8]>,
        body: &[u8],
        authenticator: &[u8],
    ) -> SmpResult<()> {
        let envelope = encrypt_client_msg(sender_secret, self.version, sender_pub_x509, body)
            .map_err(|e| format!("encrypt message: {e}"))?;
        let cmd = cmd_send(false, &envelope);
        let corr_id = self.send_command(authenticator, snd_id, &cmd)?;
        match self.wait_response(&corr_id)? {
            ServerResponse::Ok => Ok(()),
            ServerResponse::Err(e) => err(format!("сервер отверг SEND: {e}")),
            other => err(format!("неожиданный ответ на SEND: {other:?}")),
        }
    }

    /// Подписывается на очередь (`SUB`).
    /// ВАЖНО (протокол): SUB и GET несовместимы в одном соединении — сервер вернёт
    /// `ERR CMD PROHIBITED`, если в этой же сессии уже использовался GET.
    /// После SUB сервер пушит `MSG` сам, без ручного GET.
    pub fn subscribe(&mut self, rcv_id: &[u8], signing_key: &SigningKey) -> SmpResult<()> {
        let cmd = cmd_sub();
        let corr_id = new_corr_id();
        let auth = sign_command(signing_key, &self.session_id, &corr_id, rcv_id, &cmd);
        let t = Transmission {
            authenticator: &auth,
            corr_id: &corr_id,
            entity_id: rcv_id,
            command: &cmd,
        };
        let encoded = encode_transmission_v(self.version, &t).map_err(|e| format!("encode transmission: {e}"))?;
        let batch = encode_batch(&[encoded]).map_err(|e| format!("encode batch: {e}"))?;
        self.write_block(&batch)?;
        match self.wait_response(&corr_id)? {
            ServerResponse::Sok | ServerResponse::Ok => Ok(()),
            ServerResponse::Err(e) => err(format!("сервер отверг SUB: {e}")),
            other => err(format!("неожиданный ответ на SUB: {other:?}")),
        }
    }

    /// Подтверждает доставку (`ACK`).
    pub fn ack(&mut self, rcv_id: &[u8], signing_key: &SigningKey, msg_id: &[u8]) -> SmpResult<()> {
        let cmd = cmd_ack(msg_id).map_err(|e| format!("cmd ACK: {e}"))?;
        let corr_id = new_corr_id();
        let auth = sign_command(signing_key, &self.session_id, &corr_id, rcv_id, &cmd);
        let t = Transmission {
            authenticator: &auth,
            corr_id: &corr_id,
            entity_id: rcv_id,
            command: &cmd,
        };
        let encoded = encode_transmission_v(self.version, &t).map_err(|e| format!("encode transmission: {e}"))?;
        let batch = encode_batch(&[encoded]).map_err(|e| format!("encode batch: {e}"))?;
        self.write_block(&batch)?;
        match self.wait_response(&corr_id)? {
            ServerResponse::Ok => Ok(()),
            ServerResponse::Err(e) => err(format!("сервер отверг ACK: {e}")),
            other => err(format!("неожиданный ответ на ACK: {other:?}")),
        }
    }

    /// Отправляет уже собранный батч (используется для нестандартных схем авторизации).
    pub fn send_raw_batch(&mut self, batch: &[u8]) -> SmpResult<()> {
        self.write_block(batch)
    }

    /// Удаляет очередь (`DEL`).
    pub fn delete_queue(&mut self, rcv_id: &[u8], signing_key: &SigningKey) -> SmpResult<()> {
        let cmd = crate::protocols::smp::cmd_del();
        let corr_id = new_corr_id();
        let auth = sign_command(signing_key, &self.session_id, &corr_id, rcv_id, &cmd);
        let t = Transmission {
            authenticator: &auth,
            corr_id: &corr_id,
            entity_id: rcv_id,
            command: &cmd,
        };
        let encoded = encode_transmission_v(self.version, &t).map_err(|e| format!("encode transmission: {e}"))?;
        let batch = encode_batch(&[encoded]).map_err(|e| format!("encode batch: {e}"))?;
        self.write_block(&batch)?;
        match self.wait_response(&corr_id)? {
            ServerResponse::Ok => Ok(()),
            ServerResponse::Err(e) => err(format!("сервер отверг DEL: {e}")),
            other => err(format!("неожиданный ответ на DEL: {other:?}")),
        }
    }

    /// Ждёт входящее сообщение очереди (уведомление `MSG` без corrId).
    pub fn wait_message(&mut self) -> SmpResult<Vec<u8>> {
        // сначала уже накопленные
        if let Some(m) = self.pending.pop() {
            return Ok(m);
        }
        for _ in 0..64 {
            let items = self.recv_transmissions()?;
            for (_auth, corr, _entity, cmd) in items {
                if corr.is_empty() && cmd.starts_with(b"MSG ") {
                    return Ok(cmd);
                }
            }
        }
        err("сообщение не пришло")
    }

    /// Читает накопленные уведомления о сообщениях.
    pub fn take_pending(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.pending)
    }

    /// Расшифровывает принятое сообщение (серверный слой + E2E-слой).
    pub fn decrypt_received(
        &self,
        server_dh_secret: &[u8; 32],
        e2e_secret: &[u8; 32],
        msg_cmd: &[u8],
    ) -> SmpResult<(u64, Vec<u8>)> {
        let m = crate::protocols::smp::parse_msg(msg_cmd).map_err(|e| format!("parse MSG: {e}"))?;
        let body = decrypt_rcv_msg(server_dh_secret, &m.msg_id, &m.body)
            .map_err(|e| format!("decrypt server layer: {e}"))?;
        let (_, plain) =
            decrypt_client_msg(e2e_secret, &body.envelope).map_err(|e| format!("decrypt e2e: {e}"))?;
        Ok((body.timestamp, plain))
    }

    /// Формирует deniable-аутентификатор отправителя (crypto_box по серверному ключу).
    pub fn deniable_auth(
        &self,
        client_secret: &StaticSecret,
        corr_id: &[u8],
        entity_id: &[u8],
        command: &[u8],
    ) -> SmpResult<Vec<u8>> {
        let server_pub = self
            .server_session_pub
            .ok_or_else(|| "нет сессионного ключа сервера".to_string())?;
        let mut nonce = [0u8; 24];
        if corr_id.len() != 24 {
            return err("corrId должен быть 24 байта");
        }
        nonce.copy_from_slice(corr_id);
        let bytes = auth_bytes(&self.session_id, corr_id, entity_id, command);
        Ok(deniable_authenticator(&server_pub, client_secret, &nonce, &bytes))
    }

    /// Собирает transmission из команды с корректной авторизацией.
    pub fn build_signed_transmission(
        &self,
        signing_key: &SigningKey,
        corr_id: &[u8],
        entity_id: &[u8],
        command: &[u8],
    ) -> SmpResult<Vec<u8>> {
        let auth = sign_command(signing_key, &self.session_id, corr_id, entity_id, command);
        let t = Transmission {
            authenticator: &auth,
            corr_id,
            entity_id,
            command,
        };
        encode_transmission_v(self.version, &t).map_err(|e| format!("encode transmission: {e}"))
    }
}

/// Собирает короткую строку (используется в тестах и при разборе адресов).
pub fn short_str(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + bytes.len());
    let _ = put_short(&mut out, bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_parsing() {
        let a = SmpAddress::parse("smp://abc123@smp.example.org:443").unwrap();
        assert_eq!(a.host, "smp.example.org");
        assert_eq!(a.port, 443);
        assert_eq!(a.key_hash.as_deref(), Some("abc123"));
        let b = SmpAddress::parse("smp.example.org").unwrap();
        assert_eq!(b.host, "smp.example.org");
        assert_eq!(b.port, 443);
        assert!(b.key_hash.is_none());
    }

    #[test]
    fn block_roundtrip_with_chain() {
        // Проверяем обратимость шифрования блока (v11+) цепочкой ключей.
        // Клиент шлёт ck2 (сервер его читает ck2), клиент читает ck1 (сервер шлёт ck1).
        let (_, snd) = SbChainKey::init(b"sess", &[7u8; 32]);
        let (_, rcv) = SbChainKey::init(b"sess", &[7u8; 32]);
        let mut snd = snd;
        let mut rcv = rcv;
        let content = b"hello block".to_vec();
        let (sk, nonce) = snd.next();
        let padded = pad(&content, BLOCK_SIZE - 16).unwrap();
        let block = crypto_box_encrypt(&sk, &nonce, &padded);
        assert_eq!(block.len(), BLOCK_SIZE);
        let (sk2, nonce2) = rcv.next();
        let plain = crypto_box_decrypt(&sk2, &nonce2, &block).unwrap();
        assert_eq!(unpad(&plain).unwrap(), content);
    }
}
