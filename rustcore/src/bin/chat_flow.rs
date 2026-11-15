//! Host-проверка потока UI-чата: те же derive-пути, что в app-rust chat_worker.
use nexxrust::crypto;
use nexxrust::keytree;
use nexxrust::protocols::smp;
use nexxrust::protocols::smp_client::SmpClient;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

const CA: &str = include_str!("/home/thomas/.hermes/cache/scratch/smp6-5223-chain.pem");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).cloned().unwrap_or_else(|| "smp6.simplex.im:5223".into());
    let (h, p) = host.split_once(':').unwrap();
    let port: u16 = p.parse().unwrap();

    // фиксированный сид для теста (не секрет)
    let seed = crypto::sha256_raw(b"nexx ui chat flow test seed");
    let auth = ed25519_dalek::SigningKey::from_bytes(&keytree::derive_path_ed25519(&seed, "m/0'/0'/0'").unwrap().private);
    let dh = StaticSecret::from(keytree::derive_path_ed25519(&seed, "m/0'/0'/1'").unwrap().private);

    let mut client = SmpClient::connect_openssl_with_ca(h, port, Some(CA)).expect("connect");
    let ids = client.create_queue(&smp::RecipientKeys { auth_signing: auth.clone(), dh_secret: dh.clone() }).expect("NEW");
    println!("OK NEW rcv={}", crypto::hex_encode(&ids.rcv_id));

    let eph_b: [u8; 32] = crypto::random_bytes(32).try_into().unwrap();
    let eph = StaticSecret::from(eph_b);
    let eph_x = smp::x25519_x509(X25519Public::from(&eph).as_bytes());
    let e2e = eph.diffie_hellman(&X25519Public::from(&dh));
    let srv = dh.diffie_hellman(&X25519Public::from(smp::parse_x25519_x509(&ids.srv_dh_x509).unwrap()));

    client.subscribe(&ids.rcv_id, &auth).expect("SUB");
    println!("OK SUB");

    let text = "NeXX UI chat flow: hello through public relay!";
    let mut body = vec![b'_'];
    body.extend_from_slice(text.as_bytes());
    client.send_message(&ids.snd_id, e2e.as_bytes(), Some(&eph_x), &body, b"").expect("SEND");
    println!("OK SEND");

    // poll с ретраем: сначала pending (wait_response складывает туда MSG), потом сокет
    let mut got = None;
    for _ in 0..60 {
        for cmd in client.take_pending() {
            if let Ok(m) = smp::parse_msg(&cmd) {
                let rcv = smp::decrypt_rcv_msg(srv.as_bytes(), &m.msg_id, &m.body).expect("srv decrypt");
                let (_ph, plain) = smp::decrypt_client_msg(e2e.as_bytes(), &rcv.envelope).expect("e2e decrypt");
                let (_ph2, body) = smp::parse_priv_header(&plain).expect("priv header");
                got = Some(String::from_utf8_lossy(body).to_string());
                client.ack(&ids.rcv_id, &auth, &m.msg_id).expect("ACK");
            }
        }
        if got.is_some() { break; }
        match client.recv_transmissions() {
            Ok(items) => {
                for (_a, _c, _e, cmd) in items {
                    if let Ok(m) = smp::parse_msg(&cmd) {
                        let rcv = smp::decrypt_rcv_msg(srv.as_bytes(), &m.msg_id, &m.body).expect("srv decrypt");
                        let (_ph, plain) = smp::decrypt_client_msg(e2e.as_bytes(), &rcv.envelope).expect("e2e decrypt");
                        let (_ph2, body) = smp::parse_priv_header(&plain).expect("priv header");
                        got = Some(String::from_utf8_lossy(body).to_string());
                        client.ack(&ids.rcv_id, &auth, &m.msg_id).expect("ACK");
                    }
                }
            }
            Err(e) if e.contains("Resource temporarily unavailable") => {}
            Err(e) => panic!("recv: {e}"),
        }
        if got.is_some() { break; }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    match &got {
        Some(b) => println!("OK RECV decrypted: {b:?}"),
        None => println!("FAIL no message"),
    }
    assert_eq!(got.as_deref(), Some(text));

    // Регрессия: poll на пустой очереди с коротким read timeout не должен блокироваться.
    client.set_read_timeout(Some(std::time::Duration::from_millis(200)));
    let t0 = std::time::Instant::now();
    let r = client.recv_transmissions();
    let elapsed = t0.elapsed();
    match r {
        Err(e) if (e.contains("Resource temporarily unavailable") || e.contains("timed out")) && elapsed < std::time::Duration::from_secs(5) => {
            println!("OK NONBLOCK poll: тайм-аут за {:?} (не блокируется)", elapsed);
        }
        other => panic!("FAIL NONBLOCK poll: {other:?} за {elapsed:?}"),
    }

    client.delete_queue(&ids.rcv_id, &auth).expect("DEL");
    println!("OK DEL — CHAT UI FLOW OK");
}
