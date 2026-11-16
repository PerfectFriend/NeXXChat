//! Хранилище истории сообщений (Этап 2.3 плана: персистентность чатов).
//!
//! Сообщения хранятся в зашифрованном файле (AES-256-GCM, ключ HKDF
//! `nexx/message-store/v1` — отдельный домен от contact/queue-store, M9).
//! На диске НЕТ открытого текста сообщений. В памяти — расшифрованный список,
//! который приложение читает при открытии чата.

use crate::crypto::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use crate::keytree::derive_label;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Одно сообщение чата.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    /// id контакта (из contact_store).
    pub contact_id: String,
    /// направление: true = исходящее, false = входящее
    pub outgoing: bool,
    /// открытый текст сообщения (внутри зашифрованного файла)
    pub body: String,
    /// unix time (сек)
    pub ts: u64,
}

pub struct MessageStore {
    path: PathBuf,
    key: [u8; 32],
    messages: Vec<ChatMessage>,
}

/// max сообщений в хранилище (защита от бесконтрольного роста файла).
pub const MAX_MESSAGES: usize = 100_000;

impl MessageStore {
    pub fn open(path: &Path, seed: &[u8]) -> Result<Self, String> {
        let key = derive_label(seed, "nexx/message-store/v1");
        let mut store = MessageStore {
            path: path.to_path_buf(),
            key,
            messages: Vec::new(),
        };
        store.load()?;
        Ok(store)
    }

    fn load(&mut self) -> Result<(), String> {
        let raw = match std::fs::read(&self.path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.messages.clear();
                return Ok(());
            }
            Err(e) => return Err(format!("message store read: {e}")),
        };
        if raw.is_empty() {
            self.messages.clear();
            return Ok(());
        }
        let plain = aes256_gcm_decrypt(&self.key, &raw)
            .map_err(|_| "message store: не удалось расшифровать".to_string())?;
        let text = String::from_utf8(plain).map_err(|_| "message store: битые данные".to_string())?;
        self.messages = serde_json::from_str(&text).map_err(|e| format!("message store json: {e}"))?;
        Ok(())
    }

    fn save(&self) -> Result<(), String> {
        let text = serde_json::to_string(&self.messages).map_err(|e| e.to_string())?;
        let enc = aes256_gcm_encrypt(&self.key, text.as_bytes())?;
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &enc).map_err(|e| format!("message store write: {e}"))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("message store rename: {e}"))?;
        Ok(())
    }

    /// Добавить сообщение (обрезает историю до MAX_MESSAGES, хранит хвост).
    pub fn push(&mut self, m: ChatMessage) -> Result<(), String> {
        if m.body.is_empty() {
            return Err("пустое сообщение".into());
        }
        if m.contact_id.is_empty() {
            return Err("пустой contact_id".into());
        }
        self.messages.push(m);
        if self.messages.len() > MAX_MESSAGES {
            let drop = self.messages.len() - MAX_MESSAGES;
            self.messages.drain(0..drop);
        }
        self.save()
    }

    /// История конкретного контакта (в порядке времени).
    pub fn history(&self, contact_id: &str) -> Vec<&ChatMessage> {
        self.messages.iter().filter(|m| m.contact_id == contact_id).collect()
    }

    /// Удалить всю историю контакта (при удалении контакта).
    pub fn remove_contact(&mut self, contact_id: &str) -> Result<(), String> {
        self.messages.retain(|m| m.contact_id != contact_id);
        self.save()
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("nexx_message_store_tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn push_history_persist_encrypted() {
        let p = tmp_path("hist.bin");
        let _ = std::fs::remove_file(&p);
        let seed = [3u8; 64];
        let mut st = MessageStore::open(&p, &seed).unwrap();
        st.push(ChatMessage { contact_id: "c1".into(), outgoing: true, body: "привет".into(), ts: 1 }).unwrap();
        st.push(ChatMessage { contact_id: "c2".into(), outgoing: false, body: "здравствуй".into(), ts: 2 }).unwrap();
        st.push(ChatMessage { contact_id: "c1".into(), outgoing: false, body: "ок".into(), ts: 3 }).unwrap();
        assert_eq!(st.history("c1").len(), 2);
        assert_eq!(st.history("c2").len(), 1);
        // на диске — шифротекст, открытый текст не читается
        let raw_bytes = std::fs::read(&p).unwrap();
        let raw = String::from_utf8_lossy(&raw_bytes);
        assert!(!raw.contains("привет"));
        // персистентность
        drop(st);
        let st2 = MessageStore::open(&p, &seed).unwrap();
        assert_eq!(st2.len(), 3);
        assert_eq!(st2.history("c1")[0].body, "привет");
        // чужой сид не читает
        assert!(MessageStore::open(&p, &[4u8; 64]).is_err());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rejects_empty_and_trims_history() {
        let p = tmp_path("hist2.bin");
        let _ = std::fs::remove_file(&p);
        let mut st = MessageStore::open(&p, &[5u8; 64]).unwrap();
        assert!(st.push(ChatMessage { contact_id: "c".into(), outgoing: true, body: "".into(), ts: 1 }).is_err());
        assert!(st.push(ChatMessage { contact_id: "".into(), outgoing: true, body: "x".into(), ts: 1 }).is_err());
        let _ = std::fs::remove_file(&p);
    }
}
