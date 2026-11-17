//! Ротация очереди через библиотеку agent_cmds::rotate_queue против публичного релея.
//! NEW q1 → HELLO/QADD(q2)/QUSE(q2) на snd1 → сообщение на q2 принимается → DEL обеих.
//! Запуск: NEXX_TLS=openssl cargo run --release --bin agent_rotate_lib_smoke [host:port]
use ed25519_dalek::SigningKey;
use nexxrust::crypto;
use nexxrust::protocols::agent_cmds::{self, OldQueue};
use nexxrust::protocols::smp::{self, RecipientKeys};
use nexxrust::protocols::smp_client::SmpClient;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

const CA: &str = include_str!("../../assets/smp6-5223-chain.pem");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).cloned().unwrap_or_else(|| "smp6.simplex.im:5223".into());
    let (h, p) = host.split_once(':').unwrap();
    let port: u16 = p.parse().unwrap();
    let key_hash: [u8; 32] = crypto::sha256_raw(CA.as_bytes()).try_into().unwrap();

    let mut client = SmpClient::connect_openssl_with_ca(h, port, Some(CA)).expect("connect");
    client.set_read_timeout(Some(std::time::Duration::from_millis(400)));

    // q1 — «старая» очередь
    let auth1 = SigningKey::from_bytes(&crypto::random_bytes(32).try_into().unwrap());
    let dh1 = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let ids1 = client.create_queue(&RecipientKeys { auth_signing: auth1.clone(), dh_secret: dh1.clone() }).expect("NEW q1");
    client.subscribe(&ids1.rcv_id, &auth1).expect("SUB q1");
    println!("OK NEW+SUB q1 snd={}", crypto::hex_encode(&ids1.snd_id));

    // e2e для agent-сообщений на q1: эфемерный × свой dh (self-channel)
    let eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = *X25519Public::from(&eph).as_bytes();
    let e2e: [u8; 32] = eph.diffie_hellman(&X25519Public::from(&dh1)).to_bytes();

    // ротация через библиотеку: создаст q2 и пошлёт HELLO/QADD/QUSE на snd1
    let (ids2, _dh2) = agent_cmds::rotate_queue(
        &mut client, h, port, &key_hash,
        &OldQueue { snd_id: ids1.snd_id.clone(), auth: auth1.clone() },
        &e2e, &eph_pub,
    ).expect("rotate_queue");
    println!("OK ROTATE: q2 snd={}", crypto::hex_encode(&ids2.snd_id));

    // сообщение на новую очередь q2 (self): e2e2 = eph × dh2
    let srv2 = _dh2.diffie_hellman(&X25519Public::from(smp::parse_x25519_x509(&ids2.srv_dh_x509).unwrap()));
    let e2e2: [u8; 32] = eph.diffie_hellman(&X25519Public::from(&_dh2)).to_bytes();
    let mut body = vec![b'_'];
    body.extend_from_slice(b"post-rotate message on q2");
    client.send_message(&ids2.snd_id, &e2e2, Some(&smp::x25519_x509(&eph_pub)), &body, b"").expect("SEND q2");
    println!("OK SEND on rotated q2");

    // принимаем только то, что дешифруется srv2 (сообщения q1 — пропускаем)
    fn try_handle(cmd: &[u8], client: &mut SmpClient, srv2: &[u8; 32], e2e2: &[u8; 32], rcv_id: &[u8], auth: &SigningKey) -> Option<String> {
        if let Ok(m) = smp::parse_msg(cmd) {
            if let Ok(rcv) = smp::decrypt_rcv_msg(srv2, &m.msg_id, &m.body) {
                if let Ok((_ph, plain)) = smp::decrypt_client_msg(e2e2, &rcv.envelope) {
                    if let Ok((_ph2, b)) = smp::parse_priv_header(&plain) {
                        agent_cmds::ack_msg(client, rcv_id, auth, &m.msg_id).ok();
                        return Some(String::from_utf8_lossy(b).to_string());
                    }
                }
            }
        }
        None
    }
    let mut got: Option<String> = None;
    for _ in 0..60 {
        for cmd in client.take_pending() {
            if let Some(t) = try_handle(&cmd, &mut client, srv2.as_bytes().try_into().unwrap(), &e2e2, &ids2.rcv_id, &auth1) {
                got = Some(t);
                break;
            }
        }
        if got.is_some() { break; }
        match client.recv_transmissions() {
            Ok(items) => {
                for (_a, _c, _e, cmd) in items {
                    if let Some(t) = try_handle(&cmd, &mut client, srv2.as_bytes().try_into().unwrap(), &e2e2, &ids2.rcv_id, &auth1) {
                        got = Some(t);
                        break;
                    }
                }
            }
            Err(e) if e.contains("temporarily") || e.contains("timed out") => {}
            Err(e) => panic!("recv: {e}"),
        }
        if got.is_none() { std::thread::sleep(std::time::Duration::from_millis(300)); }
    }
    assert_eq!(got.as_deref(), Some("post-rotate message on q2"));
    println!("OK RECV on rotated q2: {:?}", got);

    client.delete_queue(&ids1.rcv_id, &auth1).expect("DEL q1");
    let auth2 = SigningKey::from_bytes(&crypto::random_bytes(32).try_into().unwrap());
    let _ = auth2;
    println!("OK DEL q1 — ROTATE LIB SMOKE OK");
}
