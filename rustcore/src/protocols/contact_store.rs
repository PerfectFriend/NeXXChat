//! Хранилище контактов (Этап 2.3 плана эволюции: персистентность).
//!
//! Контакт 1-1 = пара очередей (моя приёмная + принятая из инвайта) + peer-ключи.
//! Всё лежит в зашифрованном файле (AES-256-GCM, ключ = HKDF от мастер-сида,
//! метка `nexx/contact-store/v1` — domain separation от queue-store и кошелька),
//! чтобы после рестарта приложение восстанавливало контакты, а не плодило новые.
//!
//! НИКОГДА не пишет сид/приватные ключи в открытом виде: в записи только
//! публичные идентификаторы (rcvId/sndId/peer pubkey) и метаданные.

use crate::crypto::{aes256_gcm_decrypt, aes256_gcm_encrypt, hex_encode};
use crate::keytree::derive_label;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Запись контакта.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactRecord {
    /// Локальный id контакта (стабильный, например hex от peer pubkey[:8]).
    pub id: String,
    /// Отображаемое имя.
    pub name: String,
    /// Моя очередь для этого контакта: label в queue_store ("contact@{id}@host:port").
    pub my_queue_label: String,
    /// Принятая очередь пира (из connReq): rcv_id hex пира = моя snd, и наоборот.
    pub peer_rcv_id: String,
    pub peer_snd_id: String,
    /// Хост релея контакта.
    pub host: String,
    pub port: u16,
    /// Публичный ключ пира (hex, ed25519/x25519) — для сверки при QADD.
    pub peer_pub: String,
    /// connReq URI, из которого принят контакт (хранится, чтобы переподключиться).
    pub conn_req: String,
    /// Unix time создания (сек).
    pub created_at: u64,
}

/// Зашифрованное на диске хранилище контактов.
pub struct ContactStore {
    path: PathBuf,
    key: [u8; 32],
    contacts: Vec<ContactRecord>,
}

impl ContactStore {
    /// Открывает (или создаёт) хранилище. Ключ — из мастер-сида, метка
    /// `nexx/contact-store/v1` (M9: домен изолирован от fleet/wallet/proxy).
    pub fn open(path: &Path, seed: &[u8]) -> Result<Self, String> {
        let key = derive_label(seed, "nexx/contact-store/v1");
        let mut store = ContactStore {
            path: path.to_path_buf(),
            key,
            contacts: Vec::new(),
        };
        store.load()?;
        Ok(store)
    }

    fn load(&mut self) -> Result<(), String> {
        let raw = match std::fs::read(&self.path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.contacts.clear();
                return Ok(());
            }
            Err(e) => return Err(format!("contact store read: {e}")),
        };
        if raw.is_empty() {
            self.contacts.clear();
            return Ok(());
        }
        let plain = aes256_gcm_decrypt(&self.key, &raw)
            .map_err(|_| "contact store: не удалось расшифровать (неверный сид или файл повреждён)".to_string())?;
        let text = String::from_utf8(plain).map_err(|_| "contact store: битые данные".to_string())?;
        self.contacts = serde_json::from_str(&text).map_err(|e| format!("contact store json: {e}"))?;
        Ok(())
    }

    fn save(&self) -> Result<(), String> {
        let text = serde_json::to_string_pretty(&self.contacts).map_err(|e| e.to_string())?;
        let enc = aes256_gcm_encrypt(&self.key, text.as_bytes())?;
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // пишем атомарно: сначала во временный файл, потом rename —
        // чтобы падение посередине не убило хранилище.
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &enc).map_err(|e| format!("contact store write: {e}"))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("contact store rename: {e}"))?;
        Ok(())
    }

    /// Все контакты.
    pub fn contacts(&self) -> &[ContactRecord] {
        &self.contacts
    }

    /// Найти контакт по id.
    pub fn find(&self, id: &str) -> Option<&ContactRecord> {
        self.contacts.iter().find(|c| c.id == id)
    }

    /// Добавить или обновить контакт.
    pub fn upsert(&mut self, c: ContactRecord) -> Result<(), String> {
        validate_contact(&c)?;
        match self.contacts.iter_mut().find(|x| x.id == c.id) {
            Some(slot) => *slot = c,
            None => self.contacts.push(c),
        }
        self.save()
    }

    /// Удалить контакт (после DEL очередей на сервере).
    pub fn remove(&mut self, id: &str) -> Result<(), String> {
        self.contacts.retain(|c| c.id != id);
        self.save()
    }

    /// id контакта из публичного ключа пира: hex(SHA-256(pubkey)[:8]) — стабильный.
    pub fn id_for_peer_pub(peer_pub_hex: &str) -> Result<String, String> {
        let raw = crate::crypto::hex_decode(peer_pub_hex).ok_or("bad peer pub hex")?;
        let h = crate::crypto::sha256_raw(&raw);
        Ok(hex_encode(&h[..8]))
    }
}

/// Валидация записи: никаких пустых ключевых полей, никаких секретов.
pub fn validate_contact(c: &ContactRecord) -> Result<(), String> {
    if c.id.len() != 16 {
        return Err("contact id должен быть 8 байт hex (16 символов)".into());
    }
    if c.name.is_empty() {
        return Err("contact name пустое".into());
    }
    if c.my_queue_label.is_empty() {
        return Err("contact my_queue_label пустой".into());
    }
    for (field, val) in [("peer_rcv_id", &c.peer_rcv_id), ("peer_pub", &c.peer_pub)] {
        if val.is_empty() {
            return Err(format!("contact {field} пустой"));
        }
        if crate::crypto::hex_decode(val).is_none() {
            return Err(format!("contact {field} не hex"));
        }
    }
    // peer_snd_id может быть пустым до обмена очередями (QADD) — тогда не hex-проверяем
    if !c.peer_snd_id.is_empty() && crate::crypto::hex_decode(&c.peer_snd_id).is_none() {
        return Err("contact peer_snd_id не hex".into());
    }
    if c.host.is_empty() || c.port == 0 {
        return Err("contact host/port пустые".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("nexx_contact_store_tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn sample_contact(id: &str) -> ContactRecord {
        ContactRecord {
            id: id.to_string(),
            name: "Alice".into(),
            my_queue_label: format!("contact@{id}@smp6.simplex.im:5223"),
            peer_rcv_id: "ab".repeat(16),
            peer_snd_id: "cd".repeat(16),
            host: "smp6.simplex.im".into(),
            port: 5223,
            peer_pub: "ef".repeat(32),
            conn_req: "simplex://invitation#/?v=1&smp=smp6.simplex.im".into(),
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn upsert_find_remove_roundtrip() {
        let p = tmp_path("rt.bin");
        let _ = std::fs::remove_file(&p);
        let seed = [7u8; 64];
        let mut st = ContactStore::open(&p, &seed).unwrap();
        assert!(st.contacts().is_empty());
        st.upsert(sample_contact("0011223344556677")).unwrap();
        assert_eq!(st.contacts().len(), 1);
        assert!(st.find("0011223344556677").is_some());
        // персистентность: переоткрыть — контакт на месте
        drop(st);
        let st2 = ContactStore::open(&p, &seed).unwrap();
        assert_eq!(st2.contacts().len(), 1);
        assert_eq!(st2.find("0011223344556677").unwrap().name, "Alice");
        // другой сид не читает хранилище
        let st3 = ContactStore::open(&p, &[8u8; 64]);
        assert!(st3.is_err(), "чужой сид должен падать на расшифровке");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn file_on_disk_is_encrypted() {
        let p = tmp_path("enc.bin");
        let _ = std::fs::remove_file(&p);
        let mut st = ContactStore::open(&p, &[9u8; 64]).unwrap();
        st.upsert(sample_contact("aabbccddeeff0011")).unwrap();
        drop(st);
        let raw = std::fs::read(&p).unwrap();
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(!raw_str.contains("Alice"), "имя контакта не должно лежать открытым текстом");
        assert!(!raw_str.contains("smp6.simplex.im"), "хост не должен лежать открытым текстом");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn validation_rejects_bad_records() {
        let mut c = sample_contact("0011223344556677");
        c.name.clear();
        assert!(validate_contact(&c).is_err());
        let mut c = sample_contact("0011223344556677");
        c.peer_pub = "not-hex!".into();
        assert!(validate_contact(&c).is_err());
        let c = sample_contact("short");
        assert!(validate_contact(&c).is_err());
    }

    #[test]
    fn id_for_peer_pub_stable() {
        let a = ContactStore::id_for_peer_pub(&"ab".repeat(32)).unwrap();
        let b = ContactStore::id_for_peer_pub(&"ab".repeat(32)).unwrap();
        let c = ContactStore::id_for_peer_pub(&"cd".repeat(32)).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
    }
}
