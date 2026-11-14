//! Минимальный TLS-пробник: rustls vs публичный релей 5223.
use std::sync::Arc;

fn try_connect(host: &str, port: u16, provider: Arc<rustls::crypto::CryptoProvider>, label: &str) {
    // без webpki-roots: принимаем любой сертификат (пробник только про TLS-слой)
    struct NoVer;
    impl std::fmt::Debug for NoVer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "NoVer")
        }
    }
    impl rustls::client::danger::ServerCertVerifier for NoVer {
        fn verify_server_cert(&self, _e: &rustls::pki_types::CertificateDer<'_>, _i: &[rustls::pki_types::CertificateDer<'_>], _s: &rustls::pki_types::ServerName<'_>, _o: &[u8], _n: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _m: &[u8], _c: &rustls::pki_types::CertificateDer<'_>, _d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(&self, _m: &[u8], _c: &rustls::pki_types::CertificateDer<'_>, _d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![rustls::SignatureScheme::ED25519, rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::RSA_PSS_SHA256]
        }
    }
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVer))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"smp/1".to_vec()];
    let sni = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(config), sni).unwrap();
    let sock = std::net::TcpStream::connect((host, port)).unwrap();
    let mut stream = rustls::StreamOwned::new(conn, sock);
    match stream.conn.complete_io(&mut stream.sock) {
        Ok(_) if !stream.conn.is_handshaking() => {
            println!("{label}: OK alpn={:?} cipher={:?}", stream.conn.alpn_protocol(), stream.conn.negotiated_cipher_suite().map(|c| c.suite()));
            // прочитаем hello-блок
            let mut buf = vec![0u8; 16384];
            use std::io::Read;
            match stream.read(&mut buf) {
                Ok(n) => println!("{label}: server hello {n} bytes, head={}", hex(&buf[..n.min(16)])),
                Err(e) => println!("{label}: read err {e}"),
            }
        }
        Ok(_) => println!("{label}: still handshaking?!"),
        Err(e) => println!("{label}: FAIL {e}"),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let host = "smp6.simplex.im";
    let port: u16 = 5223;
    // (a) дефолтный провайдер
    try_connect(host, port, Arc::new(rustls::crypto::ring::default_provider()), "default");
    // (b) только CHACHA20 TLS1.3
    let p = rustls::crypto::CryptoProvider {
        cipher_suites: vec![rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256],
        ..rustls::crypto::ring::default_provider()
    };
    try_connect(host, port, Arc::new(p), "chacha-only");
    // (c) CHACHA + только X25519 группа
    let p2 = rustls::crypto::CryptoProvider {
        cipher_suites: vec![rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256],
        kx_groups: vec![rustls::crypto::ring::kx_group::X25519],
        ..rustls::crypto::ring::default_provider()
    };
    try_connect(host, port, Arc::new(p2), "chacha+x25519-only");
}
