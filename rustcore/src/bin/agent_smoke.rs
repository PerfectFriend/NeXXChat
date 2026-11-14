//! Агентный протокол поверх SMP (loopback против публичного релея):
//! NEW -> IDS, SEND агентного сообщения ('M' + APrivHeader + AMessage HELLO/A_MSG),
//! приём MSG, двухслойная дешифровка (server + e2e), проверка agent-фрейма, ACK, DEL.
//!
//! Запуск:
//!   NEXX_TLS=openssl cargo run --release --bin agent_smoke -- smp6.simplex.im 5223 ca.pem

use std::time::Instant;

use ed25519_dalek::SigningKey;
use nexxrust::protocols::smp::{
    decrypt_rcv_msg, encrypt_client_msg, parse_msg, parse_priv_header, x25519_x509, RecipientKeys,
};
use nexxrust::protocols::smp_client::{SmpAddress, SmpClient};
use nexxrust::protocols::smp_wire::{encode_batch, encode_transmission_v, new_corr_id, Transmission};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// smpEncode Int64 (AgentMsgId): 8 байт BE.
fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// smpEncode ByteString (MsgHash): 1-байт длина + байты.
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.push(b.len() as u8);
    out.extend_from_slice(b);
}

/// APrivHeader = (sndMsgId: Int64, prevMsgHash: ByteString)
fn a_priv_header(snd_msg_id: i64, prev_hash: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::new();
    put_i64(&mut v, snd_msg_id);
    put_bytes(&mut v, prev_hash);
    v
}

/// AgentMessage = 'M' + APrivHeader + AMessage
fn agent_msg_envelope(snd_msg_id: i64, prev_hash: &[u8; 32], a_msg: &[u8]) -> Vec<u8> {
    let mut v = vec![b'M'];
    v.extend_from_slice(&a_priv_header(snd_msg_id, prev_hash));
    v.extend_from_slice(a_msg);
    v
}

/// Разбор agent-фрейма: возвращает (sndMsgId, prevHash, aMsg tag char(s)).
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
    // ClientMessage = PrivHeader('_') + agentMsgBody
    let mut body = vec![b'_'];
    body.extend_from_slice(agent_body);
    let envelope = encrypt_client_msg(e2e_secret, client.version, Some(&x25519_x509(sender_eph_pub)), &body)
        .map_err(|e| format!("encrypt: {e}"))?;
    let cmd = nexxrust::protocols::smp::cmd_send(false, &envelope);
    let corr_id = new_corr_id();
    let t = Transmission {
        authenticator: b"",
        corr_id: &corr_id,
        entity_id: snd_id,
        command: &cmd,
    };
    let enc = encode_transmission_v(client.version, &t).map_err(|e| e.to_string())?;
    let batch = encode_batch(&[enc]).map_err(|e| e.to_string())?;
    client.send_raw_batch(&batch).map_err(|e| e.to_string())?;
    match client.wait_response(&corr_id) {
        Ok(nexxrust::protocols::smp::ServerResponse::Ok) => Ok(()),
        Ok(o) => Err(format!("SEND response: {o:?}")),
        Err(e) => Err(format!("SEND wait: {e}")),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = args.first().cloned().unwrap_or_else(|| "smp6.simplex.im:5223".into());
    let ca_path = args.get(1).cloned();
    println!("=== NeXX agent-level smoke (loopback): {target} ===");
    let t0 = Instant::now();

    let addr = match SmpAddress::parse(&target) {
        Ok(a) => a,
        Err(e) => {
            println!("FAIL address: {e}");
            std::process::exit(1);
        }
    };
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
    println!("OK  connect v{} sessionId={}B ({} ms)", client.version, client.session_id.len(), t0.elapsed().as_millis());

    client.ping().unwrap_or_else(|e| {
        println!("FAIL ping: {e}");
        std::process::exit(1);
    });
    println!("OK  PING/PONG");

    // NEW -> IDS
    let auth_signing = SigningKey::from_bytes(&[42u8; 32]);
    let dh_secret = StaticSecret::from([77u8; 32]);
    let keys = RecipientKeys {
        auth_signing: auth_signing.clone(),
        dh_secret: dh_secret.clone(),
    };
    let ids = client.create_queue(&keys).unwrap_or_else(|e| {
        println!("FAIL NEW: {e}");
        std::process::exit(1);
    });
    println!("OK  NEW -> IDS rcvId={} sndId={}", nexxrust::crypto::hex_encode(&ids.rcv_id), nexxrust::crypto::hex_encode(&ids.snd_id));

    // E2E keys (loopback: мы же и отправитель)
    let rcv_dh_pub = X25519Public::from(&dh_secret);
    let sender_eph = StaticSecret::from([99u8; 32]);
    let sender_eph_pub = X25519Public::from(&sender_eph);
    let e2e_secret = sender_eph.diffie_hellman(&rcv_dh_pub);
    let server_dh_secret = dh_secret.diffie_hellman(&X25519Public::from(
        nexxrust::protocols::smp::parse_x25519_x509(&ids.srv_dh_x509).unwrap(),
    ));

    let zero_hash = [0u8; 32];

    // --- HELLO (AMessage HELLO = "H") ---
    let hello = agent_msg_envelope(1, &zero_hash, b"H");
    send_agent_msg(&mut client, &ids.snd_id, e2e_secret.as_bytes(), sender_eph_pub.as_bytes(), &hello)
        .unwrap_or_else(|e| {
            println!("FAIL SEND HELLO: {e}");
            std::process::exit(1);
        });
    println!("OK  SEND agent HELLO accepted");

    // --- A_MSG (AMsgType "M" + Tail body) ---
    let text = "NeXX agent A_MSG roundtrip!".as_bytes();
    let mut a_msg = b"M".to_vec();
    a_msg.extend_from_slice(text);
    let h: [u8; 32] = nexxrust::crypto::sha256_raw(&hello).try_into().unwrap();
    let msg2 = agent_msg_envelope(2, &h, &a_msg);
    send_agent_msg(&mut client, &ids.snd_id, e2e_secret.as_bytes(), sender_eph_pub.as_bytes(), &msg2)
        .unwrap_or_else(|e| {
            println!("FAIL SEND A_MSG: {e}");
            std::process::exit(1);
        });
    println!("OK  SEND agent A_MSG accepted");

    // --- Принимаем оба сообщения и проверяем agent-фрейм ---
    let mut pending_msgs: Vec<Vec<u8>> = Vec::new();
    for expect in [("HELLO", "H"), ("A_MSG", "M")] {
        let msg_cmd = if let Some(m) = pending_msgs.pop() {
            m
        } else {
            client.wait_message().unwrap_or_else(|e| {
                println!("FAIL MSG: {e}");
                std::process::exit(1);
            })
        };
        let m = parse_msg(&msg_cmd).unwrap_or_else(|e| {
            println!("FAIL parse MSG: {e}");
            std::process::exit(1);
        });
        let rcv = decrypt_rcv_msg(server_dh_secret.as_bytes(), &m.msg_id, &m.body).unwrap_or_else(|e| {
            println!("FAIL server layer: {e}");
            std::process::exit(1);
        });
        let (_ph, plain) = decrypt_client_msg_loop(&e2e_secret, &rcv.envelope);
        let (_, body) = parse_priv_header(&plain).unwrap_or_else(|e| {
            println!("FAIL priv header: {e}");
            std::process::exit(1);
        });
        let (id, _hash, amsg) = parse_agent_msg(body).unwrap_or_else(|e| {
            println!("FAIL agent frame: {e}");
            std::process::exit(1);
        });
        let tag = String::from_utf8_lossy(&amsg[..amsg.len().min(2)]).to_string();
        if !tag.starts_with(expect.1) {
            println!("FAIL expected {} got tag {tag:?}", expect.0);
            std::process::exit(1);
        }
        let extra = if expect.1 == "M" {
            let t = String::from_utf8_lossy(&amsg[1..]).to_string();
            format!(" body={t:?}")
        } else {
            String::new()
        };
        println!("OK  recv agent msg #{id} type={tag}{extra}");
        // ACK может вернуться в одном batch со следующим MSG — собираем их
        let cmd_ack = nexxrust::protocols::smp::cmd_ack(&m.msg_id).unwrap();
        let corr_id = new_corr_id();
        let auth = nexxrust::protocols::smp::sign_command(&auth_signing, &client.session_id, &corr_id, &ids.rcv_id, &cmd_ack);
        let t = Transmission { authenticator: &auth, corr_id: &corr_id, entity_id: &ids.rcv_id, command: &cmd_ack };
        let enc = encode_transmission_v(client.version, &t).unwrap();
        let batch = encode_batch(&[enc]).unwrap();
        client.send_raw_batch(&batch).unwrap();
        // DEBUG: смотрим сырые ответы
        let mut resp = None;
        for _ in 0..64 {
            let items = client.recv_transmissions().unwrap();
            for (_a, corr, _e, cmd) in items {
                if corr == corr_id {
                    if cmd.starts_with(b"MSG ") {
                        // сервер доставил следующее сообщение в том же batch, что и ответ на ACK
                        pending_msgs.push(cmd);
                        resp = Some(nexxrust::protocols::smp::ServerResponse::Ok);
                    } else {
                        resp = Some(nexxrust::protocols::smp::parse_response(client.version, &cmd));
                    }
                    break;
                }
                if corr.is_empty() && cmd.starts_with(b"MSG ") {
                    pending_msgs.push(cmd);
                }
            }
            if resp.is_some() { break; }
        }
        match resp.unwrap_or(nexxrust::protocols::smp::ServerResponse::Other(b"timeout".to_vec())) {
            nexxrust::protocols::smp::ServerResponse::Ok => {}
            other => {
                println!("FAIL ACK: {other:?}");
                std::process::exit(1);
            }
        }
        pending_msgs.extend(client.take_pending());
    }
    println!("OK  ACK both messages");

    client.delete_queue(&ids.rcv_id, &auth_signing).unwrap_or_else(|e| {
        println!("FAIL DEL: {e}");
        std::process::exit(1);
    });
    println!("OK  DEL queue");
    println!("=== AGENT INTEROP OK ({} ms) ===", t0.elapsed().as_millis());
}

fn decrypt_client_msg_loop(
    e2e_secret: &x25519_dalek::SharedSecret,
    envelope: &[u8],
) -> (nexxrust::protocols::smp::ClientMsgEnvelope, Vec<u8>) {
    nexxrust::protocols::smp::decrypt_client_msg(e2e_secret.as_bytes(), envelope)
        .unwrap_or_else(|e| {
            println!("FAIL e2e decrypt: {e}");
            std::process::exit(1);
        })
}
