//! JNI-обёртки SMP-клиента: Java_com_nexx_rustcore_RustCore_smp* — мост чата в Kotlin.
//! Сессии хранятся в глобальном сторе, ответы — JSON-строки.

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::protocols::smp::{
    decrypt_client_msg, decrypt_rcv_msg, parse_msg, parse_priv_header,
    x25519_x509, RecipientKeys,
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

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

struct Session {
    client: SmpClient,
    auth: SigningKey,
    dh: StaticSecret,
    eph: StaticSecret,
    e2e: x25519_dalek::SharedSecret,
    srv: x25519_dalek::SharedSecret,
    ids: crate::protocols::smp::QueueIds,
}

static SESSIONS: Mutex<Option<HashMap<i64, Session>>> = Mutex::new(None);
static NEXT_ID: Mutex<i64> = Mutex::new(1);

fn sessions() -> std::sync::MutexGuard<'static, Option<HashMap<i64, Session>>> {
    SESSIONS.lock().unwrap()
}

fn with_session<R>(id: i64, f: impl FnOnce(&mut Session) -> R) -> Result<R, String> {
    let mut guard = sessions();
    let map = guard.as_mut().ok_or("no sessions")?;
    let s = map.get_mut(&id).ok_or("session not found")?;
    Ok(f(s))
}

/// String smpConnect(String host, int port, String caPemOrEmpty, String authSkHex, String dhSkHex)
///   -> {"ok":true,"session":N,"version":V}
/// Ключи очереди (ed25519 signing key + x25519 dh, hex) приходят из keytree на стороне
/// Kotlin — здесь НЕ должно быть дефолтных/захардкоженных ключей.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_smpConnect(
    mut env: JNIEnv,
    _class: JClass,
    host: JString,
    port: jni::sys::jint,
    ca_pem: JString,
    auth_sk_hex: JString,
    dh_sk_hex: JString,
) -> jstring {
    let host = get_str(&mut env, host);
    let ca = get_str(&mut env, ca_pem);
    let auth_hex = get_str(&mut env, auth_sk_hex);
    let dh_hex = get_str(&mut env, dh_sk_hex);
    let ca_opt = if ca.is_empty() { None } else { Some(ca) };
    let use_openssl = std::env::var("NEXX_TLS").map(|v| v == "openssl").unwrap_or(true);
    let res = (|| -> Result<String, String> {
        let auth_b = crate::crypto::hex_decode(&auth_hex).ok_or("auth key: bad hex")?;
        let dh_b = crate::crypto::hex_decode(&dh_hex).ok_or("dh key: bad hex")?;
        if auth_b.len() != 32 || dh_b.len() != 32 {
            return Err("auth/dh keys must be 32 bytes".into());
        }
        let addr = SmpAddress::parse(&format!("{host}:{port}")).map_err(|e| e.to_string())?;
        let mut client = if use_openssl {
            SmpClient::connect_openssl_with_ca(&addr.host, addr.port, ca_opt.as_deref())
        } else {
            SmpClient::connect_with_ca(&addr.host, addr.port, ca_opt.as_deref())
        }
        .map_err(|e| e.to_string())?;
        // Неблокирующий poll: read timeout 300 мс, чтобы smpPoll не блокировал JNI-поток.
        client.set_read_timeout(Some(std::time::Duration::from_millis(300)));
        let auth = SigningKey::from_bytes(&auth_b.try_into().unwrap());
        let dh_b32: [u8; 32] = dh_b.try_into().map_err(|_| "dh key: не 32 байта")?;
        let dh = StaticSecret::from(dh_b32);
        let mut eph_b = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut eph_b);
        let eph = StaticSecret::from(eph_b);
        let id = {
            let mut n = NEXT_ID.lock().unwrap();
            let id = *n;
            *n += 1;
            id
        };
        let mut guard = sessions();
        let map = guard.get_or_insert_with(HashMap::new);
        // e2e/srv считаем при создании очереди (нужен srv_dh_x509), здесь — заглушки
        let e2e = eph.diffie_hellman(&X25519Public::from(&dh));
        let srv = dh.diffie_hellman(&X25519Public::from(&dh));
        map.insert(
            id,
            Session {
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
            },
        );
        Ok(format!("{{\"ok\":true,\"session\":{id},\"version\":{}}}", map.get(&id).unwrap().client.version))
    })();
    match res {
        Ok(s) => to_jstring(&mut env, s),
        Err(e) => to_jstring(&mut env, err_json(&e)),
    }
}

/// String smpNewQueue(long session) -> {"ok":true,"rcvId":hex,"sndId":hex}
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_smpNewQueue(
    mut env: JNIEnv,
    _class: JClass,
    session: jni::sys::jlong,
) -> jstring {
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
        Ok(Ok(s)) => to_jstring(&mut env, s),
        Ok(Err(e)) => to_jstring(&mut env, err_json(&e)),
        Err(e) => to_jstring(&mut env, err_json(&e)),
    }
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
        Ok(Ok(s)) => to_jstring(&mut env, s),
        Ok(Err(e)) => to_jstring(&mut env, err_json(&e)),
        Err(e) => to_jstring(&mut env, err_json(&e)),
    }
}

/// String smpPoll(long session) -> {"ok":true,"messages":[{"msgId":hex,"body":utf8-lossy,"hex":hex}]}
/// Не блокируется: EAGAIN = пусто.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_smpPoll(
    mut env: JNIEnv,
    _class: JClass,
    session: jni::sys::jlong,
) -> jstring {
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
            let m = parse_msg(&cmd).map_err(|e| e.to_string())?;
            let rcv = decrypt_rcv_msg(s.srv.as_bytes(), &m.msg_id, &m.body).map_err(|e| format!("srv layer: {e}"))?;
            let (_ph, plain) = decrypt_client_msg(s.e2e.as_bytes(), &rcv.envelope).map_err(|e| format!("e2e: {e}"))?;
            let (_ph2, body) = parse_priv_header(&plain).map_err(|e| e.to_string())?;
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
        out.push_str("]}");
        Ok(out)
    });
    match res {
        Ok(Ok(s)) => to_jstring(&mut env, s),
        Ok(Err(e)) => to_jstring(&mut env, err_json(&e)),
        Err(e) => to_jstring(&mut env, err_json(&e)),
    }
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
    let res = with_session(session, |s| -> Result<String, String> {
        let msg_id = crate::crypto::hex_decode(&hex).ok_or("bad hex")?;
        s.client.ack(&s.ids.rcv_id, &s.auth, &msg_id).map_err(|e| e.to_string())?;
        Ok("{\"ok\":true}".to_string())
    });
    match res {
        Ok(Ok(s)) => to_jstring(&mut env, s),
        Ok(Err(e)) => to_jstring(&mut env, err_json(&e)),
        Err(e) => to_jstring(&mut env, err_json(&e)),
    }
}

/// String smpClose(long session) -> {"ok":true}
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_smpClose(
    mut env: JNIEnv,
    _class: JClass,
    session: jni::sys::jlong,
) -> jstring {
    let mut guard = sessions();
    let removed = guard.as_mut().and_then(|m| m.remove(&session));
    let s = match removed {
        Some(_) => "{\"ok\":true}",
        None => "{\"ok\":false,\"error\":\"session not found\"}",
    };
    to_jstring(&mut env, s.to_string())
}
