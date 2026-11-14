//! Боевой прогон SMP-клиента против живой инфраструктуры SimpleX.
//!
//! Сценарий: TLS+ALPN -> handshake -> PING -> NEW (очередь) -> SEND (сообщение
//! самому себе) -> получение MSG -> расшифровка -> ACK.
//!
//! Запуск:
//!   cargo run --release --bin smp_smoke -- smp6.simplex.im 443
//!   cargo run --release --bin smp_smoke -- smp://<keyHash>@host:443

use std::time::Instant;

use ed25519_dalek::SigningKey;
use nexxrust::protocols::smp::{
    decrypt_rcv_msg, ed25519_x509, encrypt_client_msg, parse_msg, parse_priv_header,
    x25519_x509, RecipientKeys,
};
use nexxrust::protocols::smp_client::{SmpAddress, SmpClient};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = args.first().cloned().unwrap_or_else(|| "smp6.simplex.im:443".into());
    let payload = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "Привет из NeXX! Проверка совместимости с SimpleX.".into());
    // Опциональный третий аргумент — путь к PEM с CA-сертификатом сервера (пиннинг).
    let ca_path = args.get(2).cloned();

    println!("=== NeXX SMP interop smoke: {target} ===");
    let t0 = Instant::now();

    // 1. Подключение + handshake.
    let mut client = match SmpAddress::parse(&target) {
        Ok(a) => {
            let ca = match &ca_path {
                Some(p) => match std::fs::read_to_string(p) {
                    Ok(txt) => Some(txt),
                    Err(e) => {
                        println!("FAIL чтение CA: {e}");
                        std::process::exit(1);
                    }
                },
                None => None,
            };
            match SmpClient::connect_with_ca(&a.host, a.port, ca.as_deref()) {
                Ok(c) => c,
                Err(e) => {
                    println!("FAIL connect: {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            println!("FAIL address: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "OK  connect: version=v{}, sessionId={}B, keyHash={}",
        client.version,
        client.session_id.len(),
        nexxrust::crypto::hex_encode(&client.key_hash)
    );
    println!(
        "OK  server session key: {}",
        client
            .server_session_pub
            .map(|k| nexxrust::crypto::hex_encode(&k))
            .unwrap_or_else(|| "none".into())
    );

    // 2. PING.
    match client.ping() {
        Ok(()) => println!("OK  PING/PONG ({} ms)", t0.elapsed().as_millis()),
        Err(e) => {
            println!("FAIL ping: {e}");
            std::process::exit(1);
        }
    }

    // 3. Ключи очереди получателя.
    let auth_signing = SigningKey::from_bytes(&[42u8; 32]);
    let dh_secret = StaticSecret::from([77u8; 32]);
    let keys = RecipientKeys {
        auth_signing: auth_signing.clone(),
        dh_secret: dh_secret.clone(),
    };

    // 4. NEW -> IDS.
    let ids = match client.create_queue(&keys) {
        Ok(ids) => ids,
        Err(e) => {
            println!("FAIL NEW: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "OK  NEW -> IDS: rcvId={} sndId={} senderCanSecure={}",
        nexxrust::crypto::hex_encode(&ids.rcv_id),
        nexxrust::crypto::hex_encode(&ids.snd_id),
        ids.sender_can_secure
    );

    // 5. Отправляем сообщение сами себе: E2E-секрет = DH(rcvQueueDhPub, senderEphPriv).
    let rcv_dh_pub = X25519Public::from(&dh_secret);
    let sender_eph = StaticSecret::from([99u8; 32]);
    let sender_eph_pub = X25519Public::from(&sender_eph);
    let e2e_secret = sender_eph.diffie_hellman(&rcv_dh_pub);

    // ClientMessage = PrivHeader + payload; пустой PrivHeader '_'.
    let mut body = Vec::new();
    body.push(b'_');
    body.extend_from_slice(payload.as_bytes());

    let envelope = match encrypt_client_msg(
        e2e_secret.as_bytes(),
        client.version,
        Some(&x25519_x509(sender_eph_pub.as_bytes())),
        &body,
    ) {
        Ok(e) => e,
        Err(e) => {
            println!("FAIL encrypt: {e}");
            std::process::exit(1);
        }
    };
    let cmd = nexxrust::protocols::smp::cmd_send(false, &envelope);
    let corr_id = nexxrust::protocols::smp_wire::new_corr_id();
    {
        use nexxrust::protocols::smp_wire::{encode_batch, encode_transmission_v, Transmission};
        let t = Transmission {
            authenticator: b"",
            corr_id: &corr_id,
            entity_id: &ids.snd_id,
            command: &cmd,
        };
        let enc = match encode_transmission_v(client.version, &t) {
            Ok(e) => e,
            Err(e) => {
                println!("FAIL encode transmission: {e}");
                std::process::exit(1);
            }
        };
        let batch = match encode_batch(&[enc]) {
            Ok(b) => b,
            Err(e) => {
                println!("FAIL encode batch: {e}");
                std::process::exit(1);
            }
        };
        if let Err(e) = client.send_raw_batch(&batch) {
            println!("FAIL send: {e}");
            std::process::exit(1);
        }
    }
    match client.wait_response(&corr_id) {
        Ok(nexxrust::protocols::smp::ServerResponse::Ok) => println!("OK  SEND accepted by server"),
        Ok(other) => {
            println!("FAIL SEND response: {other:?}");
            std::process::exit(1);
        }
        Err(e) => {
            println!("FAIL SEND wait: {e}");
            std::process::exit(1);
        }
    }

    // 6. Получаем MSG и расшифровываем.
    let msg_cmd = match client.wait_message() {
        Ok(m) => m,
        Err(e) => {
            println!("FAIL MSG: {e}");
            std::process::exit(1);
        }
    };
    let srv_dh_pub = match nexxrust::protocols::smp::parse_x25519_x509(&ids.srv_dh_x509) {
        Some(k) => k,
        None => {
            println!("FAIL: не разобрал серверный DH-ключ");
            std::process::exit(1);
        }
    };
    let server_dh_secret = dh_secret.diffie_hellman(&X25519Public::from(srv_dh_pub));
    let m = match parse_msg(&msg_cmd) {
        Ok(m) => m,
        Err(e) => {
            println!("FAIL parse MSG: {e}");
            std::process::exit(1);
        }
    };
    let rcv = match decrypt_rcv_msg(server_dh_secret.as_bytes(), &m.msg_id, &m.body) {
        Ok(r) => r,
        Err(e) => {
            println!("FAIL decrypt server layer: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "OK  MSG received: msgId={} ts={} flags={}",
        nexxrust::crypto::hex_encode(&m.msg_id),
        rcv.timestamp,
        rcv.flags as char
    );

    // E2E-слой: DH(rcvDhPriv, senderEphPub).
    let e2e_recv = dh_secret.diffie_hellman(&sender_eph_pub);
    let plain = match nexxrust::protocols::smp::decrypt_client_msg(
        e2e_recv.as_bytes(),
        &rcv.envelope,
    ) {
        Ok((_, p)) => p,
        Err(e) => {
            println!("FAIL decrypt e2e: {e}");
            std::process::exit(1);
        }
    };
    let (_hdr, text) = match parse_priv_header(&plain) {
        Ok(v) => v,
        Err(e) => {
            println!("FAIL priv header: {e}");
            std::process::exit(1);
        }
    };
    let received = String::from_utf8_lossy(text).to_string();
    if received != payload {
        println!("FAIL payload mismatch: got {received:?}, expected {payload:?}");
        std::process::exit(1);
    }
    println!("OK  payload decrypted and matches: {received:?}");

    // 7. ACK.
    match client.ack(&ids.rcv_id, &auth_signing, &m.msg_id) {
        Ok(()) => println!("OK  ACK accepted"),
        Err(e) => {
            println!("FAIL ack: {e}");
            std::process::exit(1);
        }
    }

    // 8. Уборка: удаляем очередь.
    match client.delete_queue(&ids.rcv_id, &auth_signing) {
        Ok(()) => println!("OK  DEL queue"),
        Err(e) => println!("WARN  DEL queue: {e}"),
    }

    println!("=== INTEROP OK in {} ms ===", t0.elapsed().as_millis());
    let _ = (ed25519_x509(auth_signing.verifying_key().as_bytes()), x25519_x509(rcv_dh_pub.as_bytes()));
}
