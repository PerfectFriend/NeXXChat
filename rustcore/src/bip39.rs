//! BIP39: мнемоника из энтропии, валидация, PBKDF2 seed (BIP39 стандарт: "mnemonic" + passphrase).
//! Словарь — официальный английский 2048 слов (english.txt рядом).

use crate::crypto::{pbkdf2_hmac_sha256, pbkdf2_hmac_sha512, sha256_raw};

const WORDLIST: &str = include_str!("english.txt");

pub fn wordlist() -> Vec<&'static str> {
    WORDLIST.lines().collect()
}

/// Энтропия (16/32 байта) → мнемоника (12/24 слова), checksum = первые ENT/32 бит SHA256(entropy).
pub fn mnemonic_from_entropy(entropy: &[u8]) -> Result<Vec<String>, String> {
    if entropy.len() != 16 && entropy.len() != 32 {
        return Err("entropy must be 16 or 32 bytes".into());
    }
    let words = wordlist();
    if words.len() != 2048 {
        return Err("bad wordlist".into());
    }
    let hash = sha256_raw(entropy);
    let checksum_bits = entropy.len() * 8 / 32;
    let total_bits = entropy.len() * 8 + checksum_bits;
    let mut bitstr = String::with_capacity(total_bits);
    for b in entropy.iter() {
        bitstr.push_str(&format!("{b:08b}"));
    }
    for i in 0..checksum_bits {
        let byte = hash[i / 8];
        bitstr.push(if (byte >> (7 - (i % 8))) & 1 == 1 { '1' } else { '0' });
    }
    let mut out = Vec::with_capacity(total_bits / 11);
    let mut idx = 0usize;
    while idx + 11 <= bitstr.len() {
        let v = usize::from_str_radix(&bitstr[idx..idx + 11], 2).map_err(|e| e.to_string())?;
        out.push(words[v].to_string());
        idx += 11;
    }
    Ok(out)
}

/// BIP39 seed (legacy-вариант NeXX): PBKDF2-HMAC-SHA256, 2048 итераций, 64 байта.
/// **Не совпадает со стандартом BIP39** — оставлен только для обратной совместимости
/// с уже выпущенными сборками. Новые вызовы обязаны использовать
/// [`seed_from_mnemonic`] (стандартный).
#[deprecated(note = "legacy SHA-256 вариант; используй seed_from_mnemonic (стандарт BIP39)")]
pub fn seed_from_mnemonic_legacy(mnemonic: &str, passphrase: &str) -> Vec<u8> {
    let salt = format!("mnemonic{passphrase}");
    pbkdf2_hmac_sha256(mnemonic.as_bytes(), salt.as_bytes(), 2048, 64)
}

/// BIP39 seed по стандарту: PBKDF2-HMAC-SHA512, salt = "mnemonic" + passphrase,
/// 2048 итераций, 64 байта.
///
/// Аудит H6: единая функция (SHA-512/2048) + обязательная NFKD-нормализация
/// мнемоники и passphrase — как требует BIP39. Раньше в проекте было две
/// функции (SHA-256 legacy и SHA-512), из-за чего одна мнемоника давала разные
/// сиды в зависимости от API.
pub fn seed_from_mnemonic(mnemonic: &str, passphrase: &str) -> Vec<u8> {
    use unicode_normalization::UnicodeNormalization;
    let m: String = mnemonic.nfkd().collect();
    let p: String = passphrase.nfkd().collect();
    let salt = format!("mnemonic{p}");
    pbkdf2_hmac_sha512(m.as_bytes(), salt.as_bytes(), 2048, 64)
}

/// Историческое имя стандартной функции (аудит H6: одна функция, legacy помечена).
pub fn seed_from_mnemonic_standard(mnemonic: &str, passphrase: &str) -> Vec<u8> {
    seed_from_mnemonic(mnemonic, passphrase)
}

/// Валидация: 12/24 слова, все из словаря, checksum сходится.
pub fn validate_mnemonic(words: &[String]) -> bool {
    // BIP39 допускает 12/15/18/21/24 слова (аудит H6).
    if ![12usize, 15, 18, 21, 24].contains(&words.len()) {
        return false;
    }
    let wl = wordlist();
    let mut pos: Vec<usize> = Vec::with_capacity(words.len());
    for w in words {
        match wl.iter().position(|x| *x == w) {
            Some(p) => pos.push(p),
            None => return false,
        }
    }
    let ent_bits = words.len() * 11 * 32 / 33;
    let mut bitstr = String::with_capacity(words.len() * 11);
    for p in &pos {
        bitstr.push_str(&format!("{p:011b}"));
    }
    let checksum_bits = words.len() * 11 - ent_bits;
    let ent_bytes = ent_bits / 8;
    let mut entropy = vec![0u8; ent_bytes];
    for (i, c) in bitstr[..ent_bits].chars().enumerate() {
        if c == '1' {
            entropy[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    let hash = sha256_raw(&entropy);
    for i in 0..checksum_bits {
        let expected = (hash[i / 8] >> (7 - (i % 8))) & 1;
        let actual = bitstr.as_bytes()[ent_bits + i] == b'1';
        if (expected == 1) != actual {
            return false;
        }
    }
    true
}

/// Хеш фразы для хранения (как hashSeedPhrase в Kotlin): sha256 hex от "w1 w2 ...".
pub fn hash_seed_phrase(words: &[String]) -> String {
    crate::crypto::sha256_hex(words.join(" ").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_entropy_12_words() {
        let ent = vec![0u8; 16];
        let m = mnemonic_from_entropy(&ent).unwrap();
        assert_eq!(m.len(), 12);
        assert_eq!(m[0], "abandon");
        assert_eq!(m[11], "about");
        assert!(validate_mnemonic(&m));
    }

    #[test]
    fn zero_entropy_24_words() {
        let ent = vec![0u8; 32];
        let m = mnemonic_from_entropy(&ent).unwrap();
        assert_eq!(m.len(), 24);
        assert_eq!(m[0], "abandon");
        assert_eq!(m[23], "art");
        assert!(validate_mnemonic(&m));
    }

    #[test]
    fn bad_checksum_rejected() {
        let ent = vec![0u8; 16];
        let mut m = mnemonic_from_entropy(&ent).unwrap();
        m[11] = "zoo".to_string(); // ломаем checksum
        assert!(!validate_mnemonic(&m));
    }

    #[test]
    fn wrong_len_rejected() {
        let m: Vec<String> = (0..10).map(|i| format!("word{i}")).collect();
        assert!(!validate_mnemonic(&m));
    }

    #[test]
    fn seed_deterministic() {
        let ent = vec![0u8; 16];
        let m = mnemonic_from_entropy(&ent).unwrap();
        let s1 = seed_from_mnemonic(&m.join(" "), "");
        let s2 = seed_from_mnemonic(&m.join(" "), "");
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 64);
    }
}
