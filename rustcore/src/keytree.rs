//! Универсальный источник ключей NeXX: один BIP39-сид → все ключи приложения.
//!
//! Слои:
//! 1. `MasterKey` — BIP-32 master из **стандартного** BIP39-сида (PBKDF2-HMAC-SHA512).
//! 2. `derive_secp256k1` / `derive_ed25519` — SLIP-0010 (BIP-32 для secp256k1,
//!    SLIP-0010 ed25519 для Solana-подобных путей).
//! 3. `derive_label` — HKDF-Expand от мастер-сида по строковой метке:
//!    один и тот же корень даёт независимые ключи для разных подсистем
//!    (SMP-идентичность, XFTP, хранилище ноды, чаты, кошелёк).
//!
//! Смысл для владельца ключа: из одной мнемоники поднимается **любое количество нод**
//! (индекс ноды — часть метки) и единый кошелёк, при этом приватные ключи нигде
//! не хранятся — они выводятся на лету.

use crate::crypto::{hkdf_sha256_expand, hkdf_sha256_extract, sha256_raw};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, Scalar, SecretKey};
use sha2::{Digest, Sha512};

type HmacSha512 = Hmac<Sha512>;

/// Стандартный curve order secp256k1 (n).
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Байты → элемент поля secp256k1. None, если значение ≥ n (невалидный по BIP-32).
fn scalar_from_bytes(b: &[u8; 32]) -> Option<Scalar> {
    let fb = FieldBytes::clone_from_slice(b);
    Option::from(Scalar::from_repr(fb))
}

/// Элемент поля → 32 байта big-endian.
fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&s.to_repr());
    out
}

/// Сложение по модулю n: (a + b) mod n, где a, b < n.
/// Арифметику поля делает k256::Scalar — это исключает ошибки в собственной big-int логике.
fn add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    match (scalar_from_bytes(a), scalar_from_bytes(b)) {
        (Some(sa), Some(sb)) => scalar_to_bytes(&(sa + sb)),
        _ => [0u8; 32],
    }
}

/// Расширенный ключ BIP-32: приватный ключ + chain code.
#[derive(Clone, Debug)]
pub struct XKey {
    pub private: [u8; 32],
    pub chain_code: [u8; 32],
}

/// BIP-32 master key: HMAC-SHA512("Bitcoin seed", seed).
pub fn master_secp256k1(seed: &[u8]) -> XKey {
    let i = hmac_sha512(b"Bitcoin seed", seed);
    let mut private = [0u8; 32];
    let mut chain_code = [0u8; 32];
    private.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);
    XKey {
        private,
        chain_code,
    }
}

/// SLIP-0010 master key для ed25519: HMAC-SHA512("ed25519 seed", seed).
pub fn master_ed25519(seed: &[u8]) -> XKey {
    let i = hmac_sha512(b"ed25519 seed", seed);
    let mut private = [0u8; 32];
    let mut chain_code = [0u8; 32];
    private.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);
    XKey {
        private,
        chain_code,
    }
}

/// BIP-32 CKDpriv для secp256k1: поддержаны hardened (i ≥ 2^31) и обычные индексы.
pub fn derive_secp256k1(parent: &XKey, index: u32) -> Option<XKey> {
    let mut data = Vec::with_capacity(37);
    if index >= 0x8000_0000 {
        data.push(0x00);
        data.extend_from_slice(&parent.private);
    } else {
        let sk = SecretKey::from_slice(&parent.private).ok()?;
        let pk = sk.public_key();
        data.extend_from_slice(pk.to_encoded_point(true).as_bytes());
    }
    data.extend_from_slice(&index.to_be_bytes());
    let i = hmac_sha512(&parent.chain_code, &data);
    let mut il = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    let ir = &i[32..];
    // По BIP-32: если parse256(IL) ≥ n — индекс недействителен.
    if il >= SECP256K1_N {
        return None;
    }
    // child = (parse256(IL) + kpar) mod n
    let acc = add_mod_n(&il, &parent.private);
    if acc == [0u8; 32] {
        return None;
    }
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(ir);
    Some(XKey {
        private: acc,
        chain_code,
    })
}

/// SLIP-0010 CKDpriv для ed25519 (только hardened).
pub fn derive_ed25519(parent: &XKey, index: u32) -> Option<XKey> {
    if index < 0x8000_0000 {
        return None; // ed25519 поддерживает только hardened
    }
    let mut data = Vec::with_capacity(37);
    data.push(0x00);
    data.extend_from_slice(&parent.private);
    data.extend_from_slice(&index.to_be_bytes());
    let i = hmac_sha512(&parent.chain_code, &data);
    let mut private = [0u8; 32];
    let mut chain_code = [0u8; 32];
    private.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);
    Some(XKey {
        private,
        chain_code,
    })
}

/// Путь в стиле `m/44'/60'/0'/0/0`. Разбор: `44'`, `60`, `0'` и т.п.
pub fn parse_path(path: &str) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    for part in path.split('/') {
        let part = part.trim();
        if part.is_empty() || part == "m" {
            continue;
        }
        let (num, hardened) = match part.strip_suffix('\'').or_else(|| part.strip_suffix('h')) {
            Some(n) => (n, true),
            None => (part, false),
        };
        let n: u32 = num.parse().ok()?;
        out.push(if hardened { n + 0x8000_0000 } else { n });
    }
    Some(out)
}

/// Полный путь для secp256k1.
pub fn derive_path_secp256k1(seed: &[u8], path: &str) -> Option<XKey> {
    let path = parse_path(path)?;
    let mut key = master_secp256k1(seed);
    for idx in path {
        key = derive_secp256k1(&key, idx)?;
    }
    Some(key)
}

/// Полный путь для ed25519 (SLIP-0010).
pub fn derive_path_ed25519(seed: &[u8], path: &str) -> Option<XKey> {
    let path = parse_path(path)?;
    let mut key = master_ed25519(seed);
    for idx in path {
        key = derive_ed25519(&key, idx)?;
    }
    Some(key)
}

/// Публичный ключ secp256k1 (33 байта, compressed SEC1).
pub fn secp256k1_pubkey(private: &[u8; 32]) -> Option<Vec<u8>> {
    let sk = SecretKey::from_slice(private).ok()?;
    let pk = sk.public_key();
    Some(pk.to_encoded_point(true).as_bytes().to_vec())
}

/// Ethereum-адрес (EIP-55 checksum) из публичного ключа secp256k1.
pub fn eth_address(private: &[u8; 32]) -> Option<String> {
    // uncompressed: 0x04 || X || Y → keccak256(X||Y)[12..32]
    let sk = SecretKey::from_slice(private).ok()?;
    let pk = sk.public_key();
    let uncompressed = pk.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();
    let hash = keccak256(&bytes[1..65]);
    let addr = &hash[12..32];
    Some(format_eip55(addr))
}

/// EIP-55: checksum-регистр hex-адреса (Keccak-256 от lower-case hex).
pub fn format_eip55(addr20: &[u8]) -> String {
    let hex: String = addr20.iter().map(|b| format!("{b:02x}")).collect();
    let hash = keccak256(hex.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hex.chars().enumerate() {
        let nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        if nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Bitcoin P2WPKH (bech32, native segwit) из compressed-публичного ключа.
/// hash160 = RIPEMD160(SHA256(pubkey)), далее bech32 с witness-версией 0.
pub fn btc_bech32_address(private: &[u8; 32]) -> Option<String> {
    let pk = secp256k1_pubkey(private)?;
    let h = ripemd160(&sha256_raw(&pk));
    Some(bech32_segwit("bc", &h))
}

/// RIPEMD-160.
fn ripemd160(data: &[u8]) -> [u8; 20] {
    use ripemd::Digest as _;
    let mut h = ripemd::Ripemd160::new();
    h.update(data);
    let out = h.finalize();
    let mut buf = [0u8; 20];
    buf.copy_from_slice(&out);
    buf
}

/// Bech32 (BIP-173) для witness v0: hrp + '1' + версия 0 + программа (5-бит) + checksum.
pub fn bech32_segwit(hrp: &str, program: &[u8]) -> String {
    let mut values: Vec<u8> = Vec::with_capacity(program.len() * 8 / 5 + 1);
    values.push(0); // witness version 0
    // 8 → 5 бит
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for b in program {
        acc = (acc << 8) | (*b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            values.push(((acc >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        values.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    bech32_encode_values(hrp, &values)
}

/// Bech32 (BIP-173): значения уже в 5-битном виде.
pub fn bech32_encode_values(hrp: &str, values: &[u8]) -> String {
    let charset = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut expanded = Vec::new();
    for c in hrp.bytes() {
        expanded.push(c >> 5);
    }
    expanded.push(0);
    for c in hrp.bytes() {
        expanded.push(c & 0x1f);
    }
    expanded.extend_from_slice(values);
    expanded.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let polymod = bech32_polymod(&expanded) ^ 1;
    let checksum: Vec<u8> = (0..6)
        .map(|i| ((polymod >> (5 * (5 - i))) & 0x1f) as u8)
        .collect();
    let mut out = String::from(hrp);
    out.push('1');
    for v in values.iter().copied().chain(checksum.iter().copied()) {
        out.push(charset[v as usize] as char);
    }
    out
}

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (*v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Solana-адрес (base58 от ed25519 public key) — путь m/44'/501'/0'/0'.
pub fn sol_address(seed: &[u8], path: &str) -> Option<String> {
    let key = derive_path_ed25519(seed, path)?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&key.private);
    Some(bs58::encode(signing.verifying_key().to_bytes()).into_string())
}

/// Ключ по строковой метке через HKDF-Expand от мастер-сида (domain separation).
///
/// Метка — единственный вход: `"smp/identity"`, `"node/0/storage"`, `"wallet/eth/0"` и т.п.
/// Одинаковая метка всегда даёт один и тот же ключ, разные метки — независимые ключи.
pub fn derive_label(seed: &[u8], label: &str) -> [u8; 32] {
    let prk = hkdf_sha256_extract(label.as_bytes(), seed);
    let okm = hkdf_sha256_expand(&prk, b"nexx-key-v1", 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

/// Идентификатор узла флота: 16 байт = SHA-256(pubkey)[:16] — стабильный, не секретный.
pub fn node_id(seed: &[u8], index: u32) -> [u8; 16] {
    let label = format!("node/{index}/identity");
    let priv_key = derive_label(seed, &label);
    let pubkey = secp256k1_pubkey(&priv_key).unwrap_or_else(|| priv_key.to_vec());
    let h = sha256_raw(&pubkey);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    id
}

/// План флота: N нод из одного сида. Тот же сид → тот же план на любом устройстве.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePlan {
    pub index: u32,
    pub id: String,
    pub identity_key: String,
    pub storage_key: String,
    pub chat_key: String,
}

/// Собирает план флота из N нод на одном мастер-сиде.
pub fn plan_fleet(seed: &[u8], node_count: u32) -> Vec<NodePlan> {
    (0..node_count)
        .map(|i| {
            let id = node_id(seed, i);
            let identity = derive_label(seed, &format!("node/{i}/identity"));
            let storage = derive_label(seed, &format!("node/{i}/storage"));
            let chat = derive_label(seed, &format!("node/{i}/chat"));
            NodePlan {
                index: i,
                id: id.iter().map(|b| format!("{b:02x}")).collect(),
                identity_key: identity.iter().map(|b| format!("{b:02x}")).collect(),
                storage_key: storage.iter().map(|b| format!("{b:02x}")).collect(),
                chat_key: chat.iter().map(|b| format!("{b:02x}")).collect(),
            }
        })
        .collect()
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(key).expect("HMAC принимает ключ любой длины");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&out);
    buf
}

/// Keccak-256 (Ethereum) через sha3-крейт; используется для EIP-55.
fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::Keccak256;
    let mut h = Keccak256::new();
    h.update(data);
    let out = h.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-32 test vector 1 (chaincode m и m/0').
    #[test]
    fn bip32_vector1_master_and_hardened() {
        let seed = crate::crypto::hex_decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let m = master_secp256k1(&seed);
        assert_eq!(
            m.chain_code.to_vec(),
            crate::crypto::hex_decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
                .unwrap()
        );
        assert_eq!(
            m.private.to_vec(),
            crate::crypto::hex_decode("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
                .unwrap()
        );
        let c = derive_secp256k1(&m, 0x8000_0000).unwrap();
        assert_eq!(
            c.chain_code.to_vec(),
            crate::crypto::hex_decode("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141")
                .unwrap()
        );
        assert_eq!(
            c.private.to_vec(),
            crate::crypto::hex_decode("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")
                .unwrap()
        );
        let d = derive_secp256k1(&c, 1).unwrap();
        assert_eq!(
            d.chain_code.to_vec(),
            crate::crypto::hex_decode("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19")
                .unwrap()
        );
        assert_eq!(
            d.private.to_vec(),
            crate::crypto::hex_decode("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")
                .unwrap()
        );
    }

    /// Тот же BIP-32 vector 1, но по строковому пути — парсер путей.
    #[test]
    fn bip32_vector1_by_path() {
        let seed = crate::crypto::hex_decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let k = derive_path_secp256k1(&seed, "m/0'/1").unwrap();
        assert_eq!(
            k.private.to_vec(),
            crate::crypto::hex_decode("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")
                .unwrap()
        );
    }

    /// Стандартный BIP39-сид (SHA-512) — эталонный вектор Trezor.
    #[test]
    fn bip39_standard_seed_vector() {
        let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = crate::bip39::seed_from_mnemonic_standard(m, "TREZOR");
        assert_eq!(
            crate::crypto::hex_encode(&seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
        // legacy-вариант (SHA-256) отличается — это осознанное расхождение
        let legacy = crate::bip39::seed_from_mnemonic(m, "");
        assert_ne!(legacy, seed);
    }

    /// EIP-55: контрольный адрес из BIP-55 spec.
    #[test]
    fn eip55_checksum_vectors() {
        for (addr, expect) in [
            ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
            ("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"),
            ("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"),
            ("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"),
        ] {
            let raw = crate::crypto::hex_decode(&addr[2..]).unwrap();
            assert_eq!(format_eip55(&raw), expect);
        }
    }

    /// SLIP-0010 ed25519: master key.
    #[test]
    fn slip10_ed25519_master() {
        let seed = crate::crypto::hex_decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let m = master_ed25519(&seed);
        assert_eq!(
            m.private.to_vec(),
            crate::crypto::hex_decode("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
                .unwrap()
        );
        assert_eq!(
            m.chain_code.to_vec(),
            crate::crypto::hex_decode("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb")
                .unwrap()
        );
    }

    /// ed25519: только hardened — обычный индекс возвращает None.
    #[test]
    fn ed25519_rejects_non_hardened() {
        let seed = [7u8; 32];
        let m = master_ed25519(&seed);
        assert!(derive_ed25519(&m, 1).is_none());
        assert!(derive_ed25519(&m, 0x8000_0000).is_some());
    }

    /// Ethereum-адрес детерминирован и 42 символа, checksum меняет регистр.
    #[test]
    fn eth_address_deterministic() {
        let seed = [3u8; 32];
        let k = derive_path_secp256k1(&seed, "m/44'/60'/0'/0/0").unwrap();
        let a1 = eth_address(&k.private).unwrap();
        let a2 = eth_address(&k.private).unwrap();
        assert_eq!(a1, a2);
        assert!(a1.starts_with("0x") && a1.len() == 42);
    }

    /// Solana-адрес: base58, детерминирован.
    #[test]
    fn sol_address_deterministic() {
        let seed = [9u8; 32];
        let a1 = sol_address(&seed, "m/44'/501'/0'/0'").unwrap();
        let a2 = sol_address(&seed, "m/44'/501'/0'/0'").unwrap();
        assert_eq!(a1, a2);
        assert!(a1.len() >= 32 && a1.len() <= 44);
    }

    /// Метки дают независимые ключи; одинаковая метка — одинаковый ключ.
    #[test]
    fn label_domain_separation() {
        let seed = [11u8; 32];
        let a = derive_label(&seed, "smp/identity");
        let b = derive_label(&seed, "smp/dh");
        let a2 = derive_label(&seed, "smp/identity");
        assert_eq!(a, a2);
        assert_ne!(a, b);
    }

    /// План флота: N нод из одного сида, id разные, детерминированные.
    #[test]
    fn fleet_plan_deterministic_and_unique() {
        let seed = [13u8; 32];
        let p1 = plan_fleet(&seed, 5);
        let p2 = plan_fleet(&seed, 5);
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 5);
        let mut ids: Vec<&str> = p1.iter().map(|n| n.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 5);
        // приватные ключи нод не совпадают между собой
        assert_ne!(p1[0].identity_key, p1[1].identity_key);
        assert_ne!(p1[0].storage_key, p1[1].storage_key);
    }

    /// bech32: контрольный вектор BIP-173 (witness v0).
    #[test]
    fn bech32_vector() {
        let program = crate::crypto::hex_decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        assert_eq!(
            bech32_segwit("bc", &program),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
    }
}
