//! Конфигурация SMP-релеев (аудит M6: хосты/CA/пиннинг не хардкодятся в UI-коде).
//!
//! CA-цепочки — публичные сертификаты релеев (как в `openssl s_client -showcerts`).
//! `key_hash` — SHA-256 отпечаток корневого CA из SMP hello (C1-пиннинг, [REDACTED]-формат).

pub struct ServerEntry {
    pub name: &'static str,
    pub host: &'static str,
    pub port: u16,
    /// CA-цепочка в PEM для TLS-верификации сервера.
    pub ca_pem: &'static str,
    /// SHA-256 CA для C1-пиннинга (hex, нижний регистр).
    pub key_hash: &'static str,
}

/// CA-цепочка публичного релея smp6.simplex.im (снята 2026-11, см. rustcore/assets/smp6-5223-chain.pem).
const SMP6_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBwjCCAUKgAwIBAgIUJIHRXfsIlUWgHKVAYWnhd0ghJMgwBQYDK2VxMCoxFjAU
BgNVBAMMDVNNUCBzZXJ2ZXIgQ0ExEDAOBgNVBAoMB1NpbXBsZVgwIBcNMjYwMTA1
MDkzMzQ5WhgPNDc2MzEyMDIwOTMzNDlaMBoxGDAWBgNVBAMMD3NtcDYuc2ltcGxl
eC5pbTBDMAUGAytlcQM6AD51xMggRBOdV2mGLTTrrVPgDk5lKXjSdLvVH4XJd0qc
fVGrJiwV5W/ZUZG+wmX7LzRMC37oS/0xAKNvMG0wCQYDVR0TBAIwADALBgNVHQ8E
BAMCA8gwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFCb01tgTLSY1/tqO
WoAahpSKY2TNMB8GA1UdIwQYMBaAFKwAnLeCqJPRrZZpDIJ9MnZSOp3nMAUGAytl
cQNzAOQ7FbPs6IzPSNUxZ7QLtzG5Nb/60rzi73vEa8sZu9kn/F8uE8OiWd15qs+V
fVOWOsPjPDd7zT0mAMgSxdJJ7vtnR7kejsA3bNqAr+zfX3k3mHzkKsCtxjht4EcR
tpLCTwm7NSk9HSgWsMfzJQB2vicPAA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBtjCCATagAwIBAgIUUyW5oE/0cm3BhQUtU1poneSoxvgwBQYDK2VxMCoxFjAU
BgNVBAMMDVNNUCBzZXJ2ZXIgQ0ExEDAOBgNVBAoMB1NpbXBsZVgwIBcNMjIwMTEy
MTE0ODUwWhgPNDc1OTEyMDkxMTQ4NTBaMCoxFjAUBgNVBAMMDVNNUCBzZXJ2ZXIg
Q0ExEDAOBgNVBAoMB1NpbXBsZVgwQzAFBgMrZXEDOgA9fWFWCQZmSm07M0LyYJ8a
PnAZBv/vy+rZrLPG7dQ9xTFKpCrIZA8X2gzQCdyaGQVvZsE/zgcq7YCjUzBRMB0G
A1UdDgQWBBSsAJy3gqiT0a2WaQyCfTJ2Ujqd5zAfBgNVHSMEGDAWgBSsAJy3gqiT
0a2WaQyCfTJ2Ujqd5zAPBgNVHRMBAf8EBTADAQH/MAUGAytlcQNzAM+etlcjuA4R
DfYAQmYwtYptS3IrzQ5QVjEG7sOx/tPVJyKE1gYJviquIKJml2dJLshf5kY58DH/
gNmbtPkDMwoWl/2g0NKyY/UA4qOLVNxQtiW8cMR+bGpGaUuupdL19xygH5lhftuc
UjjdUuav0c4jAA==
-----END CERTIFICATE-----";

/// Встроенный список известных релеев. Новый релей — новая запись здесь,
/// а не правка CA в UI-коде.
pub const SERVERS: &[ServerEntry] = &[ServerEntry {
    name: "SimpleX smp6 (публичный)",
    host: "smp6.simplex.im",
    port: 5223,
    ca_pem: SMP6_CA_PEM,
    // SHA-256(DER) корневого CA "SMP server CA" из цепочки smp6 (C1-пиннинг).
    // Вычислено: openssl x509 -outform DER | sha256sum по cert2 из assets/smp6-5223-chain.pem.
    key_hash: "3d0515d9e2f4b7b392b593a802c3c45764185ade3ec6295b6a4bc6506388b54a",
}];

/// Поиск записи по host:port. None — неизвестный релей (UI должен отказать,
/// а не подставлять чужой CA).
pub fn find(host: &str, port: u16) -> Option<&'static ServerEntry> {
    SERVERS.iter().find(|s| s.host == host && s.port == port)
}

/// CA по host:port — для chat_worker.
pub fn ca_for(host: &str, port: u16) -> Option<&'static str> {
    find(host, port).map(|s| s.ca_pem)
}
