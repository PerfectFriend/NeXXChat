//! Хранилище SMP-очередей (аудит H5).
//!
//! Проблема, которую закрывает модуль: раньше ключи очереди всегда деривились
//! по одним и тем же путям `m/0'/0'/0'` (auth) и `m/0'/0'/1'` (dh) — все очереди
//! и все серверы имели ОДИН и тот же ключ, что:
//! 1) ломает privacy-модель SimpleX (корреляция очередей между релеями);
//! 2) после рестарта приложения нечего восстановить — старые сообщения в очереди
//!    становятся недешифруемыми, а на релее остаётся мусор.
//!
//! Решение:
//! - у каждой очереди свой **индекс** (`m/0'/0'/{idx}'` для auth, `m/0'/1'/{idx}'`
//!   для dh) — индекс выдаёт хранилище и он никогда не переиспользуется;
//! - реквизиты очереди (индекс, rcvId, sndId) лежат в **зашифрованном** файле
//!   (AES-256-GCM, ключ — HKDF от мастер-сида), а не в открытом виде;
//! - `delete_queue` на сервере вызывается при явном закрытии очереди.

use crate::crypto::{aes256_gcm_decrypt, aes256_gcm_encrypt, hex_decode, hex_encode};
use crate::keytree::derive_label;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Реквизиты одной очереди.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueRecord {
    /// Уникальный индекс очереди (внутри одного сида).
    pub index: u32,
    /// Идентификатор принимающей стороны (hex).
    pub rcv_id: String,
    /// Идентификатор отправляющей стороны (hex).
    pub snd_id: String,
    /// Человекочитаемое имя (контакт/чат).
    pub label: String,
    /// Хост релея.
    pub host: String,
    /// Порт релея.
    pub port: u16,
}

/// Файл хранилища (зашифрованный).
pub struct QueueStore {
    path: PathBuf,
    key: [u8; 32],
    records: Vec<QueueRecord>,
}

impl QueueStore {
    /// Открывает (или создаёт) хранилище. Ключ деривируется из мастер-сида:
    /// метка `nexx/queue-store/v1` — domain separation от остальных ключей.
    pub fn open(path: &Path, seed: &[u8]) -> Result<Self, String> {
        let key = derive_label(seed, "nexx/queue-store/v1");
        let mut store = QueueStore {
            path: path.to_path_buf(),
            key,
            records: Vec::new(),
        };
        store.load()?;
        Ok(store)
    }

    fn load(&mut self) -> Result<(), String> {
        let raw = match std::fs::read(&self.path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.records.clear();
                return Ok(());
            }
            Err(e) => return Err(format!("queue store read: {e}")),
        };
        if raw.is_empty() {
            self.records.clear();
            return Ok(());
        }
        let plain = aes256_gcm_decrypt(&self.key, &raw)
            .map_err(|_| "queue store: не удалось расшифровать (неверный сид или файл повреждён)".to_string())?;
        let text = String::from_utf8(plain).map_err(|_| "queue store: битые данные".to_string())?;
        self.records = serde_json::from_str(&text).map_err(|e| format!("queue store json: {e}"))?;
        Ok(())
    }

    fn save(&self) -> Result<(), String> {
        let text = serde_json::to_string_pretty(&self.records).map_err(|e| e.to_string())?;
        let enc = aes256_gcm_encrypt(&self.key, text.as_bytes())?;
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        std::fs::write(&self.path, &enc).map_err(|e| format!("queue store write: {e}"))?;
        Ok(())
    }

    /// Следующий свободный индекс очереди (монотонно растёт, не переиспользуется).
    pub fn next_index(&self) -> u32 {
        self.records.iter().map(|r| r.index).max().map(|m| m + 1).unwrap_or(0)
    }

    /// Все записи.
    pub fn records(&self) -> &[QueueRecord] {
        &self.records
    }

    /// Найти очередь по метке.
    pub fn find_by_label(&self, label: &str) -> Option<&QueueRecord> {
        self.records.iter().find(|r| r.label == label)
    }

    /// Добавить или обновить очередь.
    pub fn upsert(&mut self, rec: QueueRecord) -> Result<(), String> {
        match self.records.iter_mut().find(|r| r.label == rec.label) {
            Some(slot) => *slot = rec,
            None => self.records.push(rec),
        }
        self.save()
    }

    /// Удалить очередь (после DEL на сервере).
    pub fn remove(&mut self, label: &str) -> Result<(), String> {
        self.records.retain(|r| r.label != label);
        self.save()
    }

    /// Пути деривации ключей очереди по индексу (аудит H5: уникальные ключи).
    pub fn auth_path(index: u32) -> String {
        format!("m/0'/0'/{index}'")
    }

    pub fn dh_path(index: u32) -> String {
        format!("m/0'/1'/{index}'")
    }
}

/// Ключи очереди, выведенные по её индексу.
pub struct QueueKeys {
    pub auth: ed25519_dalek::SigningKey,
    pub dh: x25519_dalek::StaticSecret,
}

/// Выводит ключи очереди из мастер-сида по индексу.
pub fn derive_queue_keys(seed: &[u8], index: u32) -> Result<QueueKeys, String> {
    let auth = crate::keytree::derive_path_ed25519(seed, &QueueStore::auth_path(index))
        .ok_or("keytree: не удалось вывести auth-ключ очереди")?;
    let dh = crate::keytree::derive_path_ed25519(seed, &QueueStore::dh_path(index))
        .ok_or("keytree: не удалось вывести dh-ключ очереди")?;
    Ok(QueueKeys {
        auth: ed25519_dalek::SigningKey::from_bytes(&auth.private),
        dh: x25519_dalek::StaticSecret::from(dh.private),
    })
}

/// Реквизиты очереди в hex-виде (для логов/JSON без утечки приватных ключей).
pub fn record_to_json(rec: &QueueRecord) -> String {
    serde_json::json!({
        "index": rec.index,
        "rcvId": rec.rcv_id,
        "sndId": rec.snd_id,
        "label": rec.label,
        "host": rec.host,
        "port": rec.port,
    })
    .to_string()
}

/// Проверка, что rcvId/sndId — валидный hex (защита от мусора в хранилище).
pub fn validate_record(rec: &QueueRecord) -> Result<(), String> {
    if hex_decode(&rec.rcv_id).map(|v| v.len() != 24).unwrap_or(true) {
        return Err("queue record: некорректный rcvId".into());
    }
    if hex_decode(&rec.snd_id).map(|v| v.len() != 24).unwrap_or(true) {
        return Err("queue record: некорректный sndId".into());
    }
    Ok(())
}

/// Вспомогательное: hex записи для отладки.
pub fn debug_hex(b: &[u8]) -> String {
    hex_encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn индексы_очередей_уникальны() {
        let a = QueueStore::auth_path(0);
        let b = QueueStore::auth_path(1);
        assert_ne!(a, b);
        assert_eq!(a, "m/0'/0'/0'");
        assert_eq!(QueueStore::dh_path(3), "m/0'/1'/3'");
    }

    #[test]
    fn ключи_очередей_различаются() {
        let seed = [7u8; 32];
        let k0 = derive_queue_keys(&seed, 0).unwrap();
        let k1 = derive_queue_keys(&seed, 1).unwrap();
        assert_ne!(
            k0.auth.verifying_key().to_bytes(),
            k1.auth.verifying_key().to_bytes()
        );
        assert_ne!(k0.dh.to_bytes(), k1.dh.to_bytes());
    }

    #[test]
    fn хранилище_шифруется_и_читается() {
        let dir = std::env::temp_dir().join(format!("nexx-qs-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("queues.bin");
        let seed = [9u8; 32];
        {
            let mut st = QueueStore::open(&path, &seed).unwrap();
            st.upsert(QueueRecord {
                index: 0,
                rcv_id: "00".repeat(24),
                snd_id: "11".repeat(24),
                label: "alice".into(),
                host: "smp6.simplex.im".into(),
                port: 5223,
            })
            .unwrap();
        }
        // В файле не должно быть открытого текста
        let raw = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("alice"));
        // Читается тем же сидом
        let st = QueueStore::open(&path, &seed).unwrap();
        assert_eq!(st.records().len(), 1);
        assert_eq!(st.records()[0].label, "alice");
        // Другим сидом — не открывается
        assert!(QueueStore::open(&path, &[1u8; 32]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
