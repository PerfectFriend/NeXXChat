//! SMP команды очередей против публичного релея: NEW(no sub) -> SEND -> GET -> ACK ->
//! GET (пусто, ERR NO_MSG) -> SKEY -> SEND с новым ключом -> GET -> ACK -> OFF -> DEL.
//!
//! Запуск:
//!   NEXX_TLS=openssl cargo run --release --bin smp_cmds -- smp6.simplex.im 5223 ca.pem

use std::time::Instant;

use ed25519_dalek::SigningKey;
use nexxrust::protocols::smp::{
    cmd_ack, cmd_del, cmd_get, cmd_new, cmd_off, cmd_send, cmd_skey, decrypt_rcv_msg, ed25519_x509,
    encrypt_client_msg, sign_command, x25519_x509, RecipientKeys, ServerResponse,
};
use nexxrust::protocols::smp_client::{SmpAddress, SmpClient};
use nexxrust::protocols::smp_wire::{encode_batch, encode_transmission_v, new_corr_id, Transmission};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// Отправить подписанную команду и дождаться ответа по corrId (с EAGAIN-retry).
fn cmd_signed(
    client: &mut SmpClient,
    signing_key: &SigningKey,
    entity_id: &[u8],
    cmd: &[u8],
) -> Result<ServerResponse, String> {
    let corr_id = new_corr_id();
    let auth = sign_command(signing_key, &client.session_id, &corr_id, entity_id, cmd);
    let t = Transmission { authenticator: &auth, corr_id: &corr_id, entity_id, command: cmd };
    let enc = encode_transmission_v(client.version, &t).map_err(|e| e.to_string())?;
    let batch = encode_batch(&[enc]).map_err(|e| e.to_string())?;
    client.send_raw_batch(&batch).map_err(|e| e.to_string())?;
    for _ in 0..256 {
        match client.wait_response(&corr_id) {
            Ok(r) => return Ok(r),
            Err(e) if e.contains("Resource temporarily unavailable") => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("таймаут ожидания ответа".into())
}

/// SEND без подписи (или с готовым authenticator). corr_id возвращается наружу.
fn cmd_send_raw(client: &mut SmpClient, entity_id: &[u8], authenticator: &[u8], cmd: &[u8]) -> Result<ServerResponse, String> {
    let corr_id = new_corr_id();
    cmd_raw_with_corr(client, entity_id, authenticator, cmd, &corr_id)
}

fn cmd_raw_with_corr(client: &mut SmpClient, entity_id: &[u8], authenticator: &[u8], cmd: &[u8], corr_id: &[u8]) -> Result<ServerResponse, String> {
    let t = Transmission { authenticator, corr_id, entity_id, command: cmd };
    let enc = encode_transmission_v(client.version, &t).map_err(|e| e.to_string())?;
    let batch = encode_batch(&[enc]).map_err(|e| e.to_string())?;
    client.send_raw_batch(&batch).map_err(|e| e.to_string())?;
    for _ in 0..256 {
        match client.wait_response(corr_id) {
            Ok(r) => return Ok(r),
            Err(e) if e.contains("Resource temporarily unavailable") => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("таймаут ожидания ответа".into())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = args.first().cloned().unwrap_or_else(|| "smp6.simplex.im:5223".into());
    let ca_path = args.get(1).cloned();
    println!("=== NeXX SMP commands (SUB/GET/SKEY/OFF): {target} ===");
    let t0 = Instant::now();

    let addr = SmpAddress::parse(&target).unwrap_or_else(|e| { println!("FAIL address: {e}"); std::process::exit(1); });
    let ca = ca_path.as_deref().map(|p| std::fs::read_to_string(p).unwrap());
    let use_openssl = std::env::var("NEXX_TLS").map(|v| v == "openssl").unwrap_or(true);
    let mut client = if use_openssl {
        SmpClient::connect_openssl_with_ca(&addr.host, addr.port, ca.as_deref())
    } else {
        SmpClient::connect_with_ca(&addr.host, addr.port, ca.as_deref())
    }
    .unwrap_or_else(|e| { println!("FAIL connect: {e}"); std::process::exit(1); });
    println!("OK  connect v{} ({} ms)", client.version, t0.elapsed().as_millis());

    client.ping().unwrap_or_else(|e| { println!("FAIL ping: {e}"); std::process::exit(1); });
    println!("OK  PING/PONG");

    // NEW без подписки, чтобы сообщения ждали GET
    let auth = SigningKey::from_bytes(&[42u8; 32]);
    let dh = StaticSecret::from([77u8; 32]);
    let _keys = RecipientKeys { auth_signing: auth.clone(), dh_secret: dh.clone() };
    let auth_pub = ed25519_x509(auth.verifying_key().as_bytes());
    let dh_pub = x25519_x509(X25519Public::from(&dh).as_bytes());
    let cmd = cmd_new(client.version, &auth_pub, &dh_pub, None, false, Some(b"M0"), None).unwrap();
    let corr_id = new_corr_id();
    let sig = sign_command(&auth, &client.session_id, &corr_id, b"", &cmd);
    let t = Transmission { authenticator: &sig, corr_id: &corr_id, entity_id: b"", command: &cmd };
    let enc = encode_transmission_v(client.version, &t).unwrap();
    let batch = encode_batch(&[enc]).unwrap();
    client.send_raw_batch(&batch).unwrap();
    let ids = match client.wait_response(&corr_id).unwrap() {
        ServerResponse::Ids(ids) => ids,
        other => { println!("FAIL NEW: {other:?}"); std::process::exit(1); }
    };
    println!("OK  NEW(no sub) rcv={} snd={}", nexxrust::crypto::hex_encode(&ids.rcv_id), nexxrust::crypto::hex_encode(&ids.snd_id));

    // SEND (без подписи, как первый sender) -> OK
    let eph = StaticSecret::from([99u8; 32]);
    let eph_pub = X25519Public::from(&eph);
    let e2e = eph.diffie_hellman(&X25519Public::from(&dh));
    let body = encrypt_client_msg(e2e.as_bytes(), client.version, Some(&x25519_x509(eph_pub.as_bytes())), b"hello smp_cmds").unwrap();
    let cmd = cmd_send(false, &body);
    match cmd_send_raw(&mut client, &ids.snd_id, b"", &cmd).unwrap() {
        ServerResponse::Ok => println!("OK  SEND -> OK"),
        other => { println!("FAIL SEND: {other:?}"); std::process::exit(1); }
    }

    // GET -> MSG с corrId; дешифруем server-слой
    let srv = dh.diffie_hellman(&X25519Public::from(nexxrust::protocols::smp::parse_x25519_x509(&ids.srv_dh_x509).unwrap()));
    let msg = match cmd_signed(&mut client, &auth, &ids.rcv_id, &cmd_get()).unwrap() {
        ServerResponse::Msg(m) => m,
        other => { println!("FAIL GET: {other:?}"); std::process::exit(1); }
    };
    let rcv = decrypt_rcv_msg(srv.as_bytes(), &msg.msg_id, &msg.body).unwrap_or_else(|e| {
        println!("FAIL decrypt GET body: {e}");
        std::process::exit(1);
    });
    println!("OK  GET -> MSG (server-layer дешифрован, envelope {}B)", rcv.envelope.len());

    // ACK -> OK
    match cmd_signed(&mut client, &auth, &ids.rcv_id, &cmd_ack(&msg.msg_id).unwrap()).unwrap() {
        ServerResponse::Ok => println!("OK  ACK -> OK"),
        other => { println!("FAIL ACK: {other:?}"); std::process::exit(1); }
    }

    // GET на пустой очереди -> OK или ERR NO_MSG (оба валидны для пустой очереди)
    match cmd_signed(&mut client, &auth, &ids.rcv_id, &cmd_get()).unwrap() {
        ServerResponse::Ok => println!("OK  GET (пусто) -> OK"),
        ServerResponse::Err(e) if e.contains("NO_MSG") => println!("OK  GET (пусто) -> ERR NO_MSG"),
        other => { println!("FAIL GET empty: {other:?}"); std::process::exit(1); }
    }

    // SKEY с новым ключом отправителя -> SOK (подписывается самим новым ключом)
    let snd_key = SigningKey::from_bytes(&[55u8; 32]);
    let snd_key_pub = ed25519_x509(snd_key.verifying_key().as_bytes());
    match cmd_signed(&mut client, &snd_key, &ids.snd_id, &cmd_skey(&snd_key_pub).unwrap()).unwrap() {
        ServerResponse::Sok | ServerResponse::Ok => println!("OK  SKEY -> SOK"),
        other => { println!("FAIL SKEY: {other:?}"); std::process::exit(1); }
    }

    // SEND уже подписанный новым ключом -> OK
    let body2 = encrypt_client_msg(e2e.as_bytes(), client.version, Some(&x25519_x509(eph_pub.as_bytes())), b"after SKEY").unwrap();
    let cmd2 = cmd_send(false, &body2);
    let corr2 = new_corr_id();
    let sig2 = sign_command(&snd_key, &client.session_id, &corr2, &ids.snd_id, &cmd2);
    match cmd_raw_with_corr(&mut client, &ids.snd_id, &sig2, &cmd2, &corr2).unwrap() {
        ServerResponse::Ok => println!("OK  SEND (secured, signed) -> OK"),
        other => { println!("FAIL SEND secured: {other:?}"); std::process::exit(1); }
    }

    // GET -> MSG, ACK
    let msg2 = match cmd_signed(&mut client, &auth, &ids.rcv_id, &cmd_get()).unwrap() {
        ServerResponse::Msg(m) => m,
        other => { println!("FAIL GET2: {other:?}"); std::process::exit(1); }
    };
    let _ = decrypt_rcv_msg(srv.as_bytes(), &msg2.msg_id, &msg2.body).unwrap();
    println!("OK  GET2 -> MSG (дешифрован)");
    match cmd_signed(&mut client, &auth, &ids.rcv_id, &cmd_ack(&msg2.msg_id).unwrap()).unwrap() {
        ServerResponse::Ok => println!("OK  ACK2 -> OK"),
        other => { println!("FAIL ACK2: {other:?}"); std::process::exit(1); }
    }

    // SUB -> SOK на второй очереди (в этом соединении уже использовался GET — SUB запрещён)
    let keys2 = RecipientKeys { auth_signing: auth.clone(), dh_secret: StaticSecret::from([88u8; 32]) };
    let ids2 = client.create_queue(&keys2).unwrap_or_else(|e| { println!("FAIL NEW q2: {e}"); std::process::exit(1); });
    println!("OK  NEW q2 rcv={}", nexxrust::crypto::hex_encode(&ids2.rcv_id));
    match cmd_signed(&mut client, &auth, &ids2.rcv_id, &nexxrust::protocols::smp::cmd_sub()).unwrap() {
        ServerResponse::Sok | ServerResponse::Ok => println!("OK  SUB (q2) -> SOK"),
        other => { println!("FAIL SUB: {other:?}"); std::process::exit(1); }
    }

    // OFF -> OK
    match cmd_signed(&mut client, &auth, &ids.rcv_id, &cmd_off()).unwrap() {
        ServerResponse::Ok => println!("OK  OFF -> OK"),
        other => { println!("FAIL OFF: {other:?}"); std::process::exit(1); }
    }

    // DEL -> OK (обе очереди)
    match cmd_signed(&mut client, &auth, &ids.rcv_id, &cmd_del()).unwrap() {
        ServerResponse::Ok => println!("OK  DEL q1 -> OK"),
        other => { println!("FAIL DEL q1: {other:?}"); std::process::exit(1); }
    }
    match cmd_signed(&mut client, &auth, &ids2.rcv_id, &cmd_del()).unwrap() {
        ServerResponse::Ok => println!("OK  DEL q2 -> OK"),
        other => { println!("FAIL DEL q2: {other:?}"); std::process::exit(1); }
    }

    println!("=== SMP CMDS INTEROP OK ({} ms) ===", t0.elapsed().as_millis());
}
