//! Ротация очередей поверх SMP против публичного релея (две очереди, одна сессия):
//! NEW q1, NEW q2 -> на snd1: HELLO, QADD(newQueue q2), QUSE -> на snd2: A_MSG,
//! приём всех MSG с дешифровкой (server layer per-queue + e2e), ACK всех, DEL обеих.
//!
//! Запуск:
//!   NEXX_TLS=openssl cargo run --release --bin agent_rotate -- smp6.simplex.im 5223 ca.pem

use std::time::Instant;

use ed25519_dalek::SigningKey;
use nexxrust::protocols::smp::{
    decrypt_rcv_msg, decrypt_client_msg, ed25519_x509, encrypt_client_msg, parse_msg, parse_priv_header,
    x25519_x509, RecipientKeys,
};
use nexxrust::protocols::smp_client::{SmpAddress, SmpClient};
use nexxrust::protocols::smp_wire::{encode_batch, encode_transmission_v, new_corr_id, Transmission};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
}

fn smp_router(out: &mut Vec<u8>, host: &str, port: &str, key_hash_b64: &str) {
    out.push(1);
    put_str(out, host);
    put_str(out, port);
    put_str(out, key_hash_b64);
}

fn snd_queue_addr(out: &mut Vec<u8>, host: &str, port: &str, key_hash_b64: &str, sender_id: &[u8]) {
    smp_router(out, host, port, key_hash_b64);
    out.push(sender_id.len() as u8);
    out.extend_from_slice(sender_id);
}

fn new_queue_uri(out: &mut Vec<u8>, host: &str, port: &str, key_hash_b64: &str, sender_id: &[u8], dh_x509: &[u8]) {
    out.extend_from_slice(&6u16.to_be_bytes());
    out.extend_from_slice(&20u16.to_be_bytes());
    smp_router(out, host, port, key_hash_b64);
    out.push(sender_id.len() as u8);
    out.extend_from_slice(sender_id);
    out.push(dh_x509.len() as u8);
    out.extend_from_slice(dh_x509);
    out.push(b'M');
}

fn a_priv_header(snd_msg_id: i64, prev_hash: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::new();
    put_i64(&mut v, snd_msg_id);
    v.push(prev_hash.len() as u8);
    v.extend_from_slice(prev_hash);
    v
}

fn agent_msg_envelope(snd_msg_id: i64, prev_hash: &[u8; 32], a_msg: &[u8]) -> Vec<u8> {
    let mut v = vec![b'M'];
    v.extend_from_slice(&a_priv_header(snd_msg_id, prev_hash));
    v.extend_from_slice(a_msg);
    v
}

fn parse_agent_msg(buf: &[u8]) -> Result<(i64, [u8; 32], Vec<u8>), String> {
    if buf.first() != Some(&b'M') {
        return Err(format!("ожидалась 'M', получено {:02x?}", &buf[..1]));
    }
    let mut p = 1;
    let id = i64::from_be_bytes(buf[p..p + 8].try_into().unwrap());
    p += 8;
    let hl = buf[p] as usize;
    p += 1;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&buf[p..p + hl]);
    p += hl;
    Ok((id, hash, buf[p..].to_vec()))
}

fn send_agent_msg(client: &mut SmpClient, snd_id: &[u8], e2e_secret: &[u8; 32], sender_eph_pub: &[u8; 32], agent_body: &[u8]) -> Result<(), String> {
    let mut body = vec![b'_'];
    body.extend_from_slice(agent_body);
    let envelope = encrypt_client_msg(e2e_secret, client.version, Some(&x25519_x509(sender_eph_pub)), &body)
        .map_err(|e| format!("encrypt: {e}"))?;
    let cmd = nexxrust::protocols::smp::cmd_send(false, &envelope);
    let corr_id = new_corr_id();
    let t = Transmission { authenticator: b"", corr_id: &corr_id, entity_id: snd_id, command: &cmd };
    let enc = encode_transmission_v(client.version, &t).map_err(|e| e.to_string())?;
    let batch = encode_batch(&[enc]).map_err(|e| e.to_string())?;
    client.send_raw_batch(&batch).map_err(|e| e.to_string())?;
    match client.wait_response(&corr_id) {
        Ok(nexxrust::protocols::smp::ServerResponse::Ok) => Ok(()),
        Ok(o) => Err(format!("SEND response: {o:?}")),
        Err(e) => Err(format!("SEND wait: {e}")),
    }
}

/// Ждёт следующее MSG, возвращает (rcv_id из transmission, сырой cmd).
fn wait_msg_raw(client: &mut SmpClient, pending: &mut Vec<(Vec<u8>, Vec<u8>)>) -> Result<(Vec<u8>, Vec<u8>), String> {
    if let Some(m) = pending.pop() {
        return Ok(m);
    }
    // сообщения могли накопиться во внутреннем pending клиента (их перехватил wait_response)
    for cmd in client.take_pending() {
        pending.push((Vec::new(), cmd));
    }
    if let Some(m) = pending.pop() {
        return Ok(m);
    }
    for _ in 0..256 {
        match client.recv_transmissions() {
            Ok(items) => {
                for (_auth, corr, entity, cmd) in items {
                    if cmd.starts_with(b"MSG ") && corr.is_empty() {
                        return Ok((entity, cmd));
                    }
                }
            }
            Err(e) if e.contains("Resource temporarily unavailable") => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("сообщение не пришло".into())
}

fn ack(client: &mut SmpClient, rcv_id: &[u8], auth_signing: &SigningKey, msg_id: &[u8], pending: &mut Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), String> {
    let cmd_ack = nexxrust::protocols::smp::cmd_ack(msg_id).map_err(|e| e.to_string())?;
    let corr_id = new_corr_id();
    let auth = nexxrust::protocols::smp::sign_command(auth_signing, &client.session_id, &corr_id, rcv_id, &cmd_ack);
    let t = Transmission { authenticator: &auth, corr_id: &corr_id, entity_id: rcv_id, command: &cmd_ack };
    let enc = encode_transmission_v(client.version, &t).map_err(|e| e.to_string())?;
    let batch = encode_batch(&[enc]).map_err(|e| e.to_string())?;
    client.send_raw_batch(&batch).map_err(|e| e.to_string())?;
    for _ in 0..256 {
        let items = match client.recv_transmissions() {
            Ok(i) => i,
            Err(e) if e.contains("Resource temporarily unavailable") => {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(e) => return Err(e.to_string()),
        };
        let mut done = false;
        for (_a, corr, entity, cmd) in items {
            if corr == corr_id {
                if cmd.starts_with(b"MSG ") {
                    pending.push((entity, cmd));
                    done = true; // сервер доставил следующее MSG в том же batch
                } else if cmd.starts_with(b"OK") {
                    done = true;
                } else {
                    return Err(format!("ACK response: {}", String::from_utf8_lossy(&cmd)));
                }
                break;
            }
            if corr.is_empty() && cmd.starts_with(b"MSG ") {
                pending.push((entity, cmd));
            }
        }
        if done {
            return Ok(());
        }
    }
    Err("не дождались OK на ACK".into())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = args.first().cloned().unwrap_or_else(|| "smp6.simplex.im:5223".into());
    let ca_path = args.get(1).cloned();
    println!("=== NeXX agent queue rotation: {target} ===");
    let t0 = Instant::now();

    let addr = SmpAddress::parse(&target).unwrap_or_else(|e| {
        println!("FAIL address: {e}");
        std::process::exit(1);
    });
    let ca = ca_path.as_deref().map(|p| std::fs::read_to_string(p).unwrap());
    let use_openssl = std::env::var("NEXX_TLS").map(|v| v == "openssl").unwrap_or(true);
    let mut client = if use_openssl {
        SmpClient::connect_openssl_with_ca(&addr.host, addr.port, ca.as_deref())
    } else {
        SmpClient::connect_with_ca(&addr.host, addr.port, ca.as_deref())
    }
    .unwrap_or_else(|e| {
        println!("FAIL connect: {e}");
        std::process::exit(1);
    });
    println!("OK  connect v{} ({} ms)", client.version, t0.elapsed().as_millis());

    client.ping().unwrap_or_else(|e| {
        println!("FAIL ping: {e}");
        std::process::exit(1);
    });
    println!("OK  PING/PONG");

    // --- Две очереди в одной сессии ---
    let auth1 = SigningKey::from_bytes(&[42u8; 32]);
    let dh1 = StaticSecret::from([77u8; 32]);
    let keys1 = RecipientKeys { auth_signing: auth1.clone(), dh_secret: dh1.clone() };
    let ids1 = client.create_queue(&keys1).unwrap_or_else(|e| {
        println!("FAIL NEW q1: {e}");
        std::process::exit(1);
    });
    println!("OK  NEW q1 rcv={} snd={}", nexxrust::crypto::hex_encode(&ids1.rcv_id), nexxrust::crypto::hex_encode(&ids1.snd_id));

    let auth2 = SigningKey::from_bytes(&[43u8; 32]);
    let dh2 = StaticSecret::from([78u8; 32]);
    let keys2 = RecipientKeys { auth_signing: auth2.clone(), dh_secret: dh2.clone() };
    let ids2 = client.create_queue(&keys2).unwrap_or_else(|e| {
        println!("FAIL NEW q2: {e}");
        std::process::exit(1);
    });
    println!("OK  NEW q2 rcv={} snd={}", nexxrust::crypto::hex_encode(&ids2.rcv_id), nexxrust::crypto::hex_encode(&ids2.snd_id));

    let host = addr.host.clone();
    let port = addr.port.to_string();
    let key_hash = "lrzsBiZJdvN0YHeazyjFp8_oo8Cq4RqP_O4FwL3fCMY=";

    // E2E secrets per queue
    let eph1 = StaticSecret::from([99u8; 32]);
    let eph1_pub = X25519Public::from(&eph1);
    let e2e1 = eph1.diffie_hellman(&X25519Public::from(&dh1));
    let srv1 = dh1.diffie_hellman(&X25519Public::from(nexxrust::protocols::smp::parse_x25519_x509(&ids1.srv_dh_x509).unwrap()));

    let eph2 = StaticSecret::from([100u8; 32]);
    let eph2_pub = X25519Public::from(&eph2);
    let e2e2 = eph2.diffie_hellman(&X25519Public::from(&dh2));
    let srv2 = dh2.diffie_hellman(&X25519Public::from(nexxrust::protocols::smp::parse_x25519_x509(&ids2.srv_dh_x509).unwrap()));

    let zero = [0u8; 32];
    let mut prev = zero;

    // --- q1: HELLO, QADD(q2), QUSE ---
    let hello = agent_msg_envelope(1, &prev, b"H");
    prev = nexxrust::crypto::sha256_raw(&hello).try_into().unwrap();
    send_agent_msg(&mut client, &ids1.snd_id, e2e1.as_bytes(), eph1_pub.as_bytes(), &hello).unwrap_or_else(|e| { println!("FAIL SEND HELLO: {e}"); std::process::exit(1); });
    println!("OK  SEND q1 HELLO");

    let dh2_x509 = x25519_x509(X25519Public::from(&dh2).as_bytes());
    let mut qa = b"QA".to_vec();
    qa.push(1);
    new_queue_uri(&mut qa, &host, &port, key_hash, &ids2.snd_id, &dh2_x509);
    qa.push(b'0');
    snd_queue_addr(&mut qa, &host, &port, key_hash, &ids1.snd_id);
    let qa_env = agent_msg_envelope(2, &prev, &qa);
    prev = nexxrust::crypto::sha256_raw(&qa_env).try_into().unwrap();
    send_agent_msg(&mut client, &ids1.snd_id, e2e1.as_bytes(), eph1_pub.as_bytes(), &qa_env).unwrap_or_else(|e| { println!("FAIL SEND QADD: {e}"); std::process::exit(1); });
    println!("OK  SEND q1 QADD(new queue q2)");

    let mut qu = b"QU".to_vec();
    qu.push(1);
    snd_queue_addr(&mut qu, &host, &port, key_hash, &ids2.snd_id);
    qu.push(b'T');
    let qu_env = agent_msg_envelope(3, &prev, &qu);
    prev = nexxrust::crypto::sha256_raw(&qu_env).try_into().unwrap();
    send_agent_msg(&mut client, &ids1.snd_id, e2e1.as_bytes(), eph1_pub.as_bytes(), &qu_env).unwrap_or_else(|e| { println!("FAIL SEND QUSE: {e}"); std::process::exit(1); });
    println!("OK  SEND q1 QUSE(q2 primary)");

    // --- q2: A_MSG через новую очередь ---
    let text = b"NeXX rotated to q2!";
    let mut m = b"M".to_vec();
    m.extend_from_slice(text);
    let m_env = agent_msg_envelope(1, &zero, &m);
    send_agent_msg(&mut client, &ids2.snd_id, e2e2.as_bytes(), eph2_pub.as_bytes(), &m_env).unwrap_or_else(|e| { println!("FAIL SEND q2 A_MSG: {e}"); std::process::exit(1); });
    println!("OK  SEND q2 A_MSG (новая очередь приняла)");

    // --- Приём 4 сообщений ---
    let mut pending: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut got = std::collections::HashMap::new();
    for _ in 0..4 {
        let (entity, cmd) = wait_msg_raw(&mut client, &mut pending).unwrap_or_else(|e| {
            println!("FAIL MSG: {e}");
            std::process::exit(1);
        });
        let m = parse_msg(&cmd).unwrap_or_else(|e| { println!("FAIL parse MSG: {e}"); std::process::exit(1); });
        // server layer: entity может быть пустым (взято из pending) — пробуем обе очереди
        let (server_secret, which) = if entity == ids2.rcv_id {
            (srv2.as_bytes(), 2)
        } else if entity == ids1.rcv_id {
            (srv1.as_bytes(), 1)
        } else {
            (srv1.as_bytes(), 1)
        };
        let rcv = match decrypt_rcv_msg(server_secret, &m.msg_id, &m.body) {
            Ok(r) => r,
            Err(_) if which == 1 => match decrypt_rcv_msg(srv2.as_bytes(), &m.msg_id, &m.body) {
                Ok(r) => r,
                Err(e) => {
                    println!("FAIL server layer: {e}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                println!("FAIL server layer q{which}: {e}");
                std::process::exit(1);
            }
        };
        let which = if entity.is_empty() {
            // определим по e2e: попробуем q1, иначе q2
            if decrypt_client_msg(e2e1.as_bytes(), &rcv.envelope).is_ok() { 1 } else { 2 }
        } else {
            which
        };
        let e2e = if which == 1 { &e2e1 } else { &e2e2 };
        let (_ph, plain) = decrypt_client_msg(e2e.as_bytes(), &rcv.envelope).unwrap_or_else(|e| {
            println!("FAIL e2e q{which}: {e}");
            std::process::exit(1);
        });
        let (_, body) = parse_priv_header(&plain).unwrap();
        let (id, _h, amsg) = parse_agent_msg(body).unwrap();
        let tag = String::from_utf8_lossy(&amsg[..amsg.len().min(2)]).to_string();
        let extra = if tag.starts_with('M') {
            format!(" body={:?}", String::from_utf8_lossy(&amsg[1..]))
        } else {
            String::new()
        };
        println!("OK  recv q{which} agent msg #{id} type={tag}{extra}");
        got.insert(tag[..1].to_string(), which);
        // ACK на соответствующей очереди
        let auth = if which == 1 { &auth1 } else { &auth2 };
        let rcv_id: &[u8] = if which == 1 { &ids1.rcv_id } else { &ids2.rcv_id };
        ack(&mut client, rcv_id, auth, &m.msg_id, &mut pending).unwrap_or_else(|e| {
            println!("FAIL ACK q{which}: {e}");
            std::process::exit(1);
        });
    }
    for t in ["H", "Q", "M"] {
        if !got.keys().any(|k| k.starts_with(t)) {
            println!("FAIL не получен фрейм {t}");
            std::process::exit(1);
        }
    }
    println!("OK  ACK all 4 messages");

    client.delete_queue(&ids1.rcv_id, &auth1).unwrap_or_else(|e| { println!("FAIL DEL q1: {e}"); std::process::exit(1); });
    println!("OK  DEL q1");
    client.delete_queue(&ids2.rcv_id, &auth2).unwrap_or_else(|e| { println!("FAIL DEL q2: {e}"); std::process::exit(1); });
    println!("OK  DEL q2");
    println!("=== ROTATE INTEROP OK ({} ms) ===", t0.elapsed().as_millis());
}
