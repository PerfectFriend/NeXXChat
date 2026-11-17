//! Интероп групп (Этап 4.1): два member'а (A — создатель, B) на публичном реле.
//! A создаёт группу, fan-out'ит сообщение в очередь B (per-member E2E seal),
//! B принимает, снимает оба слоя шифрования, разбирает group msg — GROUP INTEROP OK.
use nexxrust::crypto;
use nexxrust::keytree;
use nexxrust::protocols::group_store::{encode_group_msg, decode_group_msg, GroupMember, GroupMsg, GroupRecord, GroupStore};
use nexxrust::protocols::smp;
use nexxrust::protocols::smp_client::SmpClient;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

const CA: &str = include_str!("../../assets/smp6-5223-chain.pem");

fn identity(seed_phrase: &str, idx_auth: u32, idx_dh: u32) -> (ed25519_dalek::SigningKey, StaticSecret) {
    let seed = crypto::sha256_raw(seed_phrase.as_bytes());
    let auth = ed25519_dalek::SigningKey::from_bytes(
        &keytree::derive_path_ed25519(&seed, &format!("m/0'/0'/{idx_auth}'")).unwrap().private,
    );
    let dh = StaticSecret::from(
        keytree::derive_path_ed25519(&seed, &format!("m/0'/0'/{idx_dh}'")).unwrap().private,
    );
    (auth, dh)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).cloned().unwrap_or_else(|| "smp6.simplex.im:5223".into());
    let (h, p) = host.split_once(':').unwrap();
    let port: u16 = p.parse().unwrap();

    // member B: своя очередь, подписка
    let (auth_b, dh_b) = identity("nexx group smoke B", 0, 1);
    let mut client_b = SmpClient::connect_openssl_with_ca(h, port, Some(CA)).expect("connect B");
    let ids_b = client_b
        .create_queue(&smp::RecipientKeys { auth_signing: auth_b.clone(), dh_secret: dh_b.clone() })
        .expect("NEW B");
    println!("OK NEW B rcv={}", crypto::hex_encode(&ids_b.rcv_id));
    let srv_b = dh_b.diffie_hellman(&X25519Public::from(
        smp::parse_x25519_x509(&ids_b.srv_dh_x509).unwrap(),
    ));
    client_b.subscribe(&ids_b.rcv_id, &auth_b).expect("SUB B");
    println!("OK SUB B");

    // member A: своя очередь (для приёма ответов/ACK не обязателен, но создадим — честный fan-out)
    let (auth_a, dh_a) = identity("nexx group smoke A", 2, 3);
    let mut client_a = SmpClient::connect_openssl_with_ca(h, port, Some(CA)).expect("connect A");
    let ids_a = client_a
        .create_queue(&smp::RecipientKeys { auth_signing: auth_a.clone(), dh_secret: dh_a.clone() })
        .expect("NEW A");
    println!("OK NEW A rcv={}", crypto::hex_encode(&ids_a.rcv_id));

    // группа в зашифрованном сторе A
    let seed_a = crypto::sha256_raw(b"nexx group smoke A");
    let store_path = std::env::temp_dir().join("nexx_group_smoke_store.bin");
    let _ = std::fs::remove_file(&store_path);
    let mut store = GroupStore::open(&store_path, &seed_a).unwrap();
    let creator_pub_hex = crypto::hex_encode(X25519Public::from(&dh_a).as_bytes());
    let gid = GroupStore::id_for(&creator_pub_hex, "smoke", 1_700_000_000).unwrap();
    let group = GroupRecord {
        id: gid.clone(),
        name: "smoke".into(),
        creator_pub: creator_pub_hex,
        members: vec![GroupMember {
            contact_id: "b".repeat(16),
            host: h.to_string(),
            port,
            snd_id: crypto::hex_encode(&ids_b.snd_id),
            dh_pub: crypto::hex_encode(X25519Public::from(&dh_b).as_bytes()),
        }],
        created_at: 1_700_000_000,
    };
    store.upsert(group.clone()).unwrap();
    println!("OK GROUP stored id={gid} members=1");

    // fan-out: per-member E2E — один эфемерный ключ A, DH с dh_B; group msg — тело SMP-конверта.
    let msg = GroupMsg {
        v: "nexx/group/v1".into(),
        group_id: gid.clone(),
        from_contact: "a".repeat(16),
        ts: 1_700_000_001,
        body_b64: crypto::base64url_encode(b"hello group from A"),
    };
    let plain = encode_group_msg(&msg).unwrap();
    let mut eph_b = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut eph_b);
    let eph_s = StaticSecret::from(eph_b);
    let e2e_b = eph_s.diffie_hellman(&X25519Public::from(&dh_b));
    let eph_x = smp::x25519_x509(X25519Public::from(&eph_s).as_bytes());
    let mut body = vec![b'_'];
    body.extend_from_slice(&plain);
    client_a
        .send_message(&ids_b.snd_id, e2e_b.as_bytes(), Some(&eph_x), &body, b"")
        .expect("SEND to B");
    println!("OK SEND group msg -> B queue");

    // B принимает: poll, два слоя, group msg
    let mut got = None;
    for _ in 0..60 {
        for cmd in client_b.take_pending() {
            if let Ok(m) = smp::parse_msg(&cmd) {
                let rcv = smp::decrypt_rcv_msg(srv_b.as_bytes(), &m.msg_id, &m.body).expect("srv decrypt");
                let (_ph, plain2) = smp::decrypt_client_msg(e2e_b.as_bytes(), &rcv.envelope).expect("e2e decrypt");
                let (_ph2, body2) = smp::parse_priv_header(&plain2).expect("priv header");
                let gm = decode_group_msg(body2).expect("group msg");
                client_b.ack(&ids_b.rcv_id, &auth_b, &m.msg_id).expect("ACK");
                got = Some(gm);
            }
        }
        if got.is_some() {
            break;
        }
        match client_b.recv_transmissions() {
            Ok(items) => {
                for (_a, _c, _e, cmd) in items {
                    if let Ok(m) = smp::parse_msg(&cmd) {
                        let rcv = smp::decrypt_rcv_msg(srv_b.as_bytes(), &m.msg_id, &m.body).expect("srv decrypt");
                        let (_ph, plain2) = smp::decrypt_client_msg(e2e_b.as_bytes(), &rcv.envelope).expect("e2e decrypt");
                        let (_ph2, body2) = smp::parse_priv_header(&plain2).expect("priv header");
                        let gm = decode_group_msg(body2).expect("group msg");
                        client_b.ack(&ids_b.rcv_id, &auth_b, &m.msg_id).expect("ACK");
                        got = Some(gm);
                    }
                }
            }
            Err(e) if e.contains("Resource temporarily unavailable") => {}
            Err(e) => panic!("recv: {e}"),
        }
        if got.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let gm = got.expect("FAIL: B не получила групповое сообщение");
    assert_eq!(gm.group_id, gid);
    assert_eq!(crypto::base64_decode(&gm.body_b64).unwrap(), b"hello group from A");
    println!("OK RECV group msg group_id={} body=hello group from A", gm.group_id);

    client_b.delete_queue(&ids_b.rcv_id, &auth_b).expect("DEL B");
    client_a.delete_queue(&ids_a.rcv_id, &auth_a).expect("DEL A");
    println!("OK DEL — GROUP INTEROP OK");
}
