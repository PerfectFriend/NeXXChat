//! Группы (Этап 4.1 плана эволюции): шифрованное хранилище групп + фрейминг
//! групповых сообщений.
//!
//! Модель: группа = id + имя + список member'ов, у каждого своя очередь-адрес
//! (host/port/snd_id) и DH-публичный ключ для E2E. Сообщение в группу —
//! fan-out: per-member шифрование (crypto_box, eph sender × member dh pub)
//! и отправка в очередь каждого member'а (см. bin/group_smoke.rs).
//!
//! Хранилище на диске — AES-256-GCM, ключ HKDF метка `nexx/group-store/v1`
//! (M9 domain separation). В открытом виде на диске ничего нет.

use crate::crypto::{aes256_gcm_decrypt, aes256_gcm_encrypt, hex_decode, hex_encode, sha256_raw};
use crate::keytree::derive_label;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Member группы: куда слать (очередь) и чем шифровать (публичный ключ).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// id контакта из contact_store.
    pub contact_id: String,
    pub host: String,
    pub port: u16,
    /// snd_id очереди member'а (hex) — из QADD/connReq.
    pub snd_id: String,
    /// X25519 публичный ключ member'а (hex, 32 байта) — для E2E.
    pub dh_pub: String,
}

/// Запись группы.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRecord {
    /// id группы: hex(SHA-256(creator_pub || name || created_at)[:8]).
    pub id: String,
    pub name: String,
    /// Публичный ключ создателя (hex) — для id и аудита.
    pub creator_pub: String,
    pub members: Vec<GroupMember>,
    pub created_at: u64,
}

/// Зашифрованное хранилище групп.
pub struct GroupStore {
    path: PathBuf,
    key: [u8; 32],
    groups: Vec<GroupRecord>,
}

impl GroupStore {
    /// Открыть/создать. Ключ — HKDF от мастер-сида, метка `nexx/group-store/v1`.
    pub fn open(path: &Path, seed: &[u8]) -> Result<Self, String> {
        let key = derive_label(seed, "nexx/group-store/v1");
        let mut store = GroupStore {
            path: path.to_path_buf(),
            key,
            groups: Vec::new(),
        };
        store.load()?;
        Ok(store)
    }

    fn load(&mut self) -> Result<(), String> {
        let raw = match std::fs::read(&self.path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.groups.clear();
                return Ok(());
            }
            Err(e) => return Err(format!("group store read: {e}")),
        };
        if raw.is_empty() {
            self.groups.clear();
            return Ok(());
        }
        let plain = aes256_gcm_decrypt(&self.key, &raw)
            .map_err(|_| "group store: не удалось расшифровать (неверный сид или битый файл)".to_string())?;
        let text = String::from_utf8(plain).map_err(|_| "group store: битые данные".to_string())?;
        self.groups = serde_json::from_str(&text).map_err(|e| format!("group store json: {e}"))?;
        Ok(())
    }

    fn save(&self) -> Result<(), String> {
        let text = serde_json::to_string_pretty(&self.groups).map_err(|e| e.to_string())?;
        let enc = aes256_gcm_encrypt(&self.key, text.as_bytes())?;
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &enc).map_err(|e| format!("group store write: {e}"))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("group store rename: {e}"))?;
        Ok(())
    }

    pub fn groups(&self) -> &[GroupRecord] {
        &self.groups
    }

    pub fn find(&self, id: &str) -> Option<&GroupRecord> {
        self.groups.iter().find(|g| g.id == id)
    }

    pub fn upsert(&mut self, g: GroupRecord) -> Result<(), String> {
        validate_group(&g)?;
        match self.groups.iter_mut().find(|x| x.id == g.id) {
            Some(slot) => *slot = g,
            None => self.groups.push(g),
        }
        self.save()
    }

    pub fn remove(&mut self, id: &str) -> Result<(), String> {
        self.groups.retain(|g| g.id != id);
        self.save()
    }

    /// Стабильный id группы из публичных данных.
    pub fn id_for(creator_pub_hex: &str, name: &str, created_at: u64) -> Result<String, String> {
        let raw = hex_decode(creator_pub_hex).ok_or("bad creator pub hex")?;
        let mut buf = raw;
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&created_at.to_be_bytes());
        Ok(hex_encode(&sha256_raw(&buf)[..8]))
    }
}

/// Валидация: никаких пустых полей, hex-проверки, без дублей member'ов.
pub fn validate_group(g: &GroupRecord) -> Result<(), String> {
    if g.id.len() != 16 || hex_decode(&g.id).is_none() {
        return Err("group id должен быть 8 байт hex".into());
    }
    if g.name.is_empty() {
        return Err("group name пустое".into());
    }
    if hex_decode(&g.creator_pub).is_none() {
        return Err("group creator_pub не hex".into());
    }
    // пустой список member'ов допустим: группа создаётся раньше, чем в неё
    // добавлены контакты (после QADD); непустые записи валидируются ниже.
    let mut seen = std::collections::HashSet::new();
    for m in &g.members {
        if !seen.insert(m.contact_id.clone()) {
            return Err(format!("дубль member contact_id {}", m.contact_id));
        }
        if m.host.is_empty() || m.port == 0 {
            return Err("member host/port пустые".into());
        }
        if hex_decode(&m.snd_id).is_none() {
            return Err("member snd_id не hex".into());
        }
        let dh = hex_decode(&m.dh_pub).ok_or("member dh_pub не hex")?;
        if dh.len() != 32 {
            return Err("member dh_pub должен быть 32 байта".into());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Фрейминг группового сообщения (внутри E2E-конверта)
// ---------------------------------------------------------------------------

/// Групповое сообщение: JSON с телом в base64 — стабильный фрейм для fan-out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMsg {
    /// "nexx/group/v1" — тег протокола.
    pub v: String,
    pub group_id: String,
    pub from_contact: String,
    pub ts: u64,
    /// Тело сообщения (base64 в JSON).
    pub body_b64: String,
}

pub fn encode_group_msg(m: &GroupMsg) -> Result<Vec<u8>, String> {
    if m.v != "nexx/group/v1" {
        return Err("неизвестная версия группового сообщения".into());
    }
    serde_json::to_vec(m).map_err(|e| e.to_string())
}

pub fn decode_group_msg(raw: &[u8]) -> Result<GroupMsg, String> {
    let m: GroupMsg = serde_json::from_slice(raw).map_err(|e| format!("group msg json: {e}"))?;
    if m.v != "nexx/group/v1" {
        return Err("неизвестная версия группового сообщения".into());
    }
    if m.group_id.len() != 16 || hex_decode(&m.group_id).is_none() {
        return Err("group_id не hex".into());
    }
    if m.from_contact.is_empty() {
        return Err("from_contact пустой".into());
    }
    if crate::crypto::base64_decode(&m.body_b64).is_err() {
        return Err("body_b64 не base64".into());
    }
    Ok(m)
}

/// Sealed-конверт для одного member'а: eph_x25519 pub (для DH) + crypto_box ciphertext.
/// Возвращает (eph_pub_raw_32, ciphertext). Расшифровка: crypto_box_decrypt(member_dh_secret, nonce, ct)
/// с eph_pub — см. тесты и bin/group_smoke.rs.
pub fn seal_for_member(
    member_dh_pub: &[u8; 32],
    plaintext: &[u8],
) -> Result<([u8; 32], Vec<u8>), String> {
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};
    let mut eph_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut eph_bytes);
    let eph = StaticSecret::from(eph_bytes);
    let shared = eph.diffie_hellman(&PublicKey::from(*member_dh_pub));
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = crate::protocols::smp::crypto_box_encrypt(shared.as_bytes(), &nonce, plaintext);
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok((*PublicKey::from(&eph).as_bytes(), out))
}

/// Открыть конверт member'ом.
pub fn open_for_member(
    member_dh_secret: &[u8; 32],
    sender_eph_pub: &[u8; 32],
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    use x25519_dalek::{PublicKey, StaticSecret};
    if sealed.len() < 24 {
        return Err("sealed слишком короткий".into());
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&sealed[..24]);
    let shared = StaticSecret::from(*member_dh_secret).diffie_hellman(&PublicKey::from(*sender_eph_pub));
    crate::protocols::smp::crypto_box_decrypt(shared.as_bytes(), &nonce, &sealed[24..])
        .map_err(|e| format!("open group msg: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("nexx_group_store_tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn sample_group(id: &str) -> GroupRecord {
        GroupRecord {
            id: id.into(),
            name: "NeXX dev".into(),
            creator_pub: "ab".repeat(32),
            members: vec![GroupMember {
                contact_id: "0011223344556677".into(),
                host: "smp6.simplex.im".into(),
                port: 5223,
                snd_id: "cd".repeat(16),
                dh_pub: "ef".repeat(32),
            }],
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn upsert_find_remove_roundtrip() {
        let p = tmp_path("rt.bin");
        let _ = std::fs::remove_file(&p);
        let seed = [3u8; 64];
        let mut st = GroupStore::open(&p, &seed).unwrap();
        st.upsert(sample_group("aabbccddeeff0011")).unwrap();
        assert_eq!(st.groups().len(), 1);
        drop(st);
        let st2 = GroupStore::open(&p, &seed).unwrap();
        assert_eq!(st2.find("aabbccddeeff0011").unwrap().name, "NeXX dev");
        assert!(GroupStore::open(&p, &[4u8; 64]).is_err(), "чужой сид не читает");
        let mut st2 = st2;
        st2.remove("aabbccddeeff0011").ok();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn file_on_disk_is_encrypted() {
        let p = tmp_path("enc.bin");
        let _ = std::fs::remove_file(&p);
        let mut st = GroupStore::open(&p, &[5u8; 64]).unwrap();
        st.upsert(sample_group("1122334455667788")).unwrap();
        drop(st);
        let raw = std::fs::read(&p).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(!s.contains("NeXX dev"));
        assert!(!s.contains("smp6.simplex.im"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn validation_rejects_bad_groups() {
        let mut g = sample_group("aabbccddeeff0011");
        g.members.clear();
        assert!(validate_group(&g).is_ok(), "пустая группа (до добавления member'ов) валидна");
        let mut g = sample_group("aabbccddeeff0011");
        g.members[0].dh_pub = "zz".repeat(32);
        assert!(validate_group(&g).is_err());
        let g = sample_group("short");
        assert!(validate_group(&g).is_err());
        let mut g = sample_group("aabbccddeeff0011");
        g.members.push(g.members[0].clone());
        assert!(validate_group(&g).is_err(), "дубль member'а");
    }

    #[test]
    fn group_msg_roundtrip() {
        let m = GroupMsg {
            v: "nexx/group/v1".into(),
            group_id: "aabbccddeeff0011".into(),
            from_contact: "0011223344556677".into(),
            ts: 1_700_000_000,
            body_b64: crate::crypto::base64url_encode(b"hello group"),
        };
        let enc = encode_group_msg(&m).unwrap();
        let dec = decode_group_msg(&enc).unwrap();
        assert_eq!(dec.group_id, m.group_id);
        assert_eq!(crate::crypto::base64_decode(&dec.body_b64).unwrap(), b"hello group");
        // битый тег версии
        let mut bad = enc.clone();
        bad.splice(8..10, b"v2".to_vec());
        assert!(decode_group_msg(&bad).is_err() || decode_group_msg(&bad).unwrap().v != "nexx/group/v1");
    }

    #[test]
    fn seal_open_for_member_roundtrip() {
        use x25519_dalek::{PublicKey, StaticSecret};
        let member_sec = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let member_pub = PublicKey::from(&member_sec);
        let msg = encode_group_msg(&GroupMsg {
            v: "nexx/group/v1".into(),
            group_id: "aabbccddeeff0011".into(),
            from_contact: "0011223344556677".into(),
            ts: 42,
            body_b64: crate::crypto::base64url_encode(b"ping"),
        })
        .unwrap();
        let (eph_pub, sealed) = seal_for_member(member_pub.as_bytes(), &msg).unwrap();
        let opened = open_for_member(member_sec.as_bytes(), &eph_pub, &sealed).unwrap();
        assert_eq!(opened, msg);
        // чужой ключ не открывает
        let other = StaticSecret::random_from_rng(rand::rngs::OsRng);
        assert!(open_for_member(other.as_bytes(), &eph_pub, &sealed).is_err());
    }
}
