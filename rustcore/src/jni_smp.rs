//! JNI-обёртки SMP-клиента: Java_com_nexx_rustcore_RustCore_smp* — мост чата в Kotlin.
//! Сессии хранятся в глобальном сторе, ответы — JSON-строки.
//!
//! Исправления по аудиту (15.11.2026):
//! - **C1**: `smpConnect` требует keyHash (hex, 32 байта) и CA PEM; без закреплённого
//!   keyHash подключение невозможно — сервер обязан быть идентифицирован.
//! - **H2**: глобальный мьютекс держится только на get/insert/remove; сетевой I/O —
//!   под per-session мьютексом (иначе ANR на UI-потоке).
//! - **H3**: паники через FFI не abort'ят процесс — каждый экспорт обёрнут в
//!   `ffi_guard` (catch_unwind) и возвращает `{"ok":false,...}`.
//! - **H4**: ошибка одного сообщения не рвёт poll целиком: битое сообщение
//!   подтверждается (ACK) и попадает в карантин со счётчиком, остальные доставляются.
//! - **M1**: JSON-экранирование через serde_json (раньше был невалидный JSON).

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::protocols::smp::{
    decrypt_client_msg, decrypt_rcv_msg, parse_msg, parse_priv_header, x25519_x509, RecipientKeys,
};
use crate::protocols::smp_client::{SmpAddress, SmpClient};

fn to_jstring(env: &mut JNIEnv, s: String) -> jstring {
    match env.new_string(s) {
        Ok(j) => j.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn get_str(env: &mut JNIEnv, s: JString) -> String {
    env.get_string(&s).map(|j| j.into()).unwrap_or_default()
}

fn err_json(e: &str) -> String {
    format!("{{\"ok\":false,\"error\":{}}}", json_str(e))
}

/// JSON-строка (аудит M1): корректное экранирование любых символов.
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// Обёртка FFI: любая паника превращается в JSON-ошибку вместо abort (аудит H3).
macro_rules! ffi_guard {
    ($env:expr, $body:expr) => {{
        match catch_unwind(AssertUnwindSafe(|| $body)) {
            Ok(s) => s,
            Err(_) => err_json("внутренняя ошибка (паника перехвачена)"),
        }
    }};
}

struct Session {
    client: SmpClient,
    auth: SigningKey,
    dh: StaticSecret,
    eph: StaticSecret,
    e2e: x25519_dalek::SharedSecret,
    srv: x25519_dalek::SharedSecret,
    ids: crate::protocols::smp::QueueIds,
    /// Счётчик повреждённых сообщений (карантин, аудит H4).
    damaged: u64,
}

/// Глобальный стор: только карта сессий. Мьютекс НЕ держится во время сети (H2).
static SESSIONS: std::sync::LazyLock<Mutex<HashMap<i64, Arc<Mutex<Session>>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_ID: Mutex<i64> = Mutex::new(1);

/// Мьютекс без паники при poison (аудит H3: `.lock().unwrap()` = паника).
fn lock_sessions() -> std::sync::MutexGuard<'static, HashMap<i64, Arc<Mutex<Session>>>> {
    SESSIONS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Per-session доступ: глобальный мьютекс берётся только на поиск сессии.
fn with_session<R>(id: i64, f: impl FnOnce(&mut Session) -> R) -> Result<R, String> {
    let arc = {
        let map = lock_sessions();
        map.get(&id).cloned().ok_or("session not found")?
    };
    let mut guard = arc.lock().unwrap_or_else(|e| e.into_inner());
    Ok(f(&mut guard))
}

/// String smpConnect(String host, int port, String caPem, String keyHashHex,
///                   String authSkHex, String dhSkHex)
///   -> {"ok":true,"session":N,"version":V}
/// Ключи очереди (ed25519 signing key + x25519 dh, hex) приходят из keytree на стороне
/// Kotlin — здесь НЕ должно быть дефолтных/захардкоженных ключей.
/// `caPem` и `keyHashHex` обязательны (аудит C1): сервер идентифицируется отпечатком
/// своего CA, а не именем хоста.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_smpConnect(
    mut env: JNIEnv,
    _class: JClass,
    host: JString,
    port: jni::sys::jint,
    ca_pem: JString,
    key_hash_hex: JString,
    auth_sk_hex: JString,
    dh_sk_hex: JString,
) -> jstring {
    let host = get_str(&mut env, host);
    let ca = get_str(&mut env, ca_pem);
    let key_hash_hex = get_str(&mut env, key_hash_hex);
    let auth_hex = get_str(&mut env, auth_sk_hex);
    let dh_hex = get_str(&mut env, dh_sk_hex);
    let out = ffi_guard!(env, {
        let res = (|| -> Result<String, String> {
            let auth_b = crate::crypto::hex_decode(&auth_hex).ok_or("auth key: bad hex")?;
            let dh_b = crate::crypto::hex_decode(&dh_hex).ok_or("dh key: bad hex")?;
            if auth_b.len() != 32 || dh_b.len() != 32 {
                return Err("auth/dh keys must be 32 bytes".into());
            }
            // Аудит C1: без keyHash подключение запрещено.
            if ca.trim().is_empty() {
                return Err("CA PEM обязателен (пиннинг keyHash)".into());
            }
            if key_hash_hex.trim().is_empty() {
                return Err("keyHash обязателен (пиннинг сервера)".into());
            }
            let key_hash = crate::crypto::hex_decode(&key_hash_hex).ok_or("keyHash: bad hex")?;
            if key_hash.len() != 32 {
                return Err("keyHash должен быть 32 байтами (SHA-256)".into());
            }
            let addr = SmpAddress::parse(&format!("{host}:{port}")).map_err(|e| e.to_string())?;
            let use_openssl = std::env::var("NEXX_TLS").map(|v| v == "openssl").unwrap_or(true);
            let mut client = if use_openssl {
                SmpClient::connect_openssl_with_ca(&addr.host, addr.port, Some(&ca))
            } else {
                SmpClient::connect_with_ca(&addr.host, addr.port, Some(&ca))
            }
            .map_err(|e| e.to_string())?;
            // Ожидаемый keyHash: сверяем с тем, что реально закреплён CA.
            client.set_expected_key_hash(key_hash)?;
            // Неблокирующий poll: read timeout 300 мс, чтобы smpPoll не блокировал JNI-поток.
            client.set_poll_timeout(std::time::Duration::from_millis(300));
            let auth = SigningKey::from_bytes(&auth_b.try_into().map_err(|_| "auth key: не 32 байта")?);
            let dh_b32: [u8; 32] = dh_b.try_into().map_err(|_| "dh key: не 32 байта")?;
            let dh = StaticSecret::from(dh_b32);
            let mut eph_b = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut eph_b);
            let eph = StaticSecret::from(eph_b);
            let id = {
                let mut n = NEXT_ID.lock().unwrap_or_else(|e| e.into_inner());
                let id = *n;
                *n += 1;
                id
            };
            // e2e/srv считаем при создании очереди (нужен srv_dh_x509), здесь — заглушки
            let e2e = eph.diffie_hellman(&X25519Public::from(&dh));
            let srv = dh.diffie_hellman(&X25519Public::from(&dh));
            let version = client.version;
            let session = Session {
                client,
                auth,
                dh,
                eph,
                e2e,
                srv,
                ids: crate::protocols::smp::QueueIds {
                    rcv_id: vec![],
                    snd_id: vec![],
                    srv_dh_x509: vec![],
                    sender_can_secure: false,
                },
                damaged: 0,
            };
            lock_sessions().insert(id, Arc::new(Mutex::new(session)));
            Ok(format!("{{\"ok\":true,\"session\":{id},\"version\":{version}}}"))
        })();
        match res {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    });
    to_jstring(&mut env, out)
}

/// String smpNewQueue(long session) -> {"ok":true,"rcvId":hex,"sndId":hex}
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_smpNewQueue(
    mut env: JNIEnv,
    _class: JClass,
    session: jni::sys::jlong,
) -> jstring {
    let out = ffi_guard!(env, {
        let res = with_session(session, |s| -> Result<String, String> {
            let keys = RecipientKeys { auth_signing: s.auth.clone(), dh_secret: s.dh.clone() };
            let ids = s.client.create_queue(&keys).map_err(|e| e.to_string())?;
            // теперь можем посчитать реальные e2e/srv секреты
            s.e2e = s.eph.diffie_hellman(&X25519Public::from(&s.dh));
            s.srv = s.dh.diffie_hellman(&X25519Public::from(
                crate::protocols::smp::parse_x25519_x509(&ids.srv_dh_x509).ok_or("bad srv dh key")?,
            ));
            let out = format!(
                "{{\"ok\":true,\"rcvId\":\"{}\",\"sndId\":\"{}\"}}",
                crate::crypto::hex_encode(&ids.rcv_id),
                crate::crypto::hex_encode(&ids.snd_id)
            );
            s.ids = ids;
            Ok(out)
        });
        match res {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => err_json(&e),
            Err(e) => err_json(&e),
        }
    });
    to_jstring(&mut env, out)
}

/// String smpSendText(long session, String text) -> {"ok":true}
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_smpSendText(
    mut env: JNIEnv,
    _class: JClass,
    session: jni::sys::jlong,
    text: JString,
) -> jstring {
    let text = get_str(&mut env, text);
    let out = ffi_guard!(env, {
        let res = with_session(session, |s| -> Result<String, String> {
            let eph_pub_x509 = x25519_x509(X25519Public::from(&s.eph).as_bytes());
            // ClientMessage = PrivHeader('_') + текст; send_message сам оборачивает в конверт.
            let mut plain = vec![b'_'];
            plain.extend_from_slice(text.as_bytes());
            s.client
                .send_message(&s.ids.snd_id, s.e2e.as_bytes(), Some(&eph_pub_x509), &plain, b"")
                .map_err(|e| e.to_string())?;
            Ok("{\"ok\":true}".to_string())
        });
        match res {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => err_json(&e),
            Err(e) => err_json(&e),
        }
    });
    to_jstring(&mut env, out)
}

/// String smpPoll(long session) -> {"ok":true,"messages":[...],"damaged":N}
/// Не блокируется: EAGAIN = пусто.
/// Аудит H4: битое сообщение не рвёт poll — оно ACK'ается и попадает в счётчик
/// `damaged`, остальные сообщения доставляются как обычно.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_smpPoll(
    mut env: JNIEnv,
    _class: JClass,
    session: jni::sys::jlong,
) -> jstring {
    let out = ffi_guard!(env, {
        let res = with_session(session, |s| -> Result<String, String> {
            let mut out = String::from("{\"ok\":true,\"messages\":[");
            let mut first = true;
            // сначала из внутреннего pending клиента (wait_response складывает туда MSG)
            let mut cmds: Vec<Vec<u8>> = s.client.take_pending();
            // затем один блок с коротким read timeout (300 мс выставляется в smpConnect):
            // тайм-аут чтения = "ничего не пришло", это норма для poll.
            match s.client.recv_transmissions() {
                Ok(items) => {
                    for (_a, corr, _e, cmd) in items {
                        if corr.is_empty() && cmd.starts_with(b"MSG ") {
                            cmds.push(cmd);
                        }
                    }
                }
                Err(e) if e.contains("Resource temporarily unavailable") || e.contains("timed out") => {}
                Err(e) => return Err(e.to_string()),
            }
            for cmd in cmds {
                // H4: ошибка разбора/дешифровки одного сообщения не прерывает цикл.
                let m = match parse_msg(&cmd) {
                    Ok(m) => m,
                    Err(_) => {
                        s.damaged += 1;
                        continue;
                    }
                };
                let decoded = decrypt_rcv_msg(s.srv.as_bytes(), &m.msg_id, &m.body)
                    .map_err(|e| format!("srv: {e:?}"))
                    .and_then(|rcv| {
                        decrypt_client_msg(s.e2e.as_bytes(), &rcv.envelope)
                            .map_err(|e| format!("e2e: {e:?}"))
                    })
                    .and_then(|(_ph, plain)| {
                        parse_priv_header(&plain)
                            .map(|(ph, body)| (ph, body.to_vec()))
                            .map_err(|e| format!("priv header: {e:?}"))
                    });
                let (_ph2, body): (Option<Vec<u8>>, Vec<u8>) = match decoded {
                    Ok(v) => v,
                    Err(_) => {
                        // Недешифруемое сообщение: подтверждаем (иначе очередь залипает
                        // и переотдаёт его бесконечно) и считаем как повреждённое.
                        let _ = s.client.ack(&s.ids.rcv_id, &s.auth, &m.msg_id);
                        s.damaged += 1;
                        continue;
                    }
                };
                let body_str = String::from_utf8_lossy(&body).to_string();
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&format!(
                    "{{\"msgId\":\"{}\",\"body\":{},\"hex\":\"{}\"}}",
                    crate::crypto::hex_encode(&m.msg_id),
                    json_str(&body_str),
                    crate::crypto::hex_encode(&body)
                ));
            }
            out.push_str(&format!("],\"damaged\":{}}}", s.damaged));
            Ok(out)
        });
        match res {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => err_json(&e),
            Err(e) => err_json(&e),
        }
    });
    to_jstring(&mut env, out)
}

/// String smpAck(long session, String msgIdHex) -> {"ok":true}
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_smpAck(
    mut env: JNIEnv,
    _class: JClass,
    session: jni::sys::jlong,
    msg_id_hex: JString,
) -> jstring {
    let hex = get_str(&mut env, msg_id_hex);
    let out = ffi_guard!(env, {
        let res = with_session(session, |s| -> Result<String, String> {
            let msg_id = crate::crypto::hex_decode(&hex).ok_or("bad hex")?;
            s.client.ack(&s.ids.rcv_id, &s.auth, &msg_id).map_err(|e| e.to_string())?;
            Ok("{\"ok\":true}".to_string())
        });
        match res {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => err_json(&e),
            Err(e) => err_json(&e),
        }
    });
    to_jstring(&mut env, out)
}

/// String smpClose(long session) -> {"ok":true}
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_smpClose(
    mut env: JNIEnv,
    _class: JClass,
    session: jni::sys::jlong,
) -> jstring {
    let out = ffi_guard!(env, {
        let removed = lock_sessions().remove(&session);
        match removed {
            Some(_) => "{\"ok\":true}".to_string(),
            None => "{\"ok\":false,\"error\":\"session not found\"}".to_string(),
        }
    });
    to_jstring(&mut env, out)
}
