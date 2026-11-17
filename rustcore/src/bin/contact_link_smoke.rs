//! Живой интероп contact_link: Alice↔Bob через публичный релей, чат в обе стороны.
//! Запуск: NEXX_TLS=openssl cargo run --release --bin contact_link_smoke [host:port]
use nexxrust::crypto;
use nexxrust::protocols::connreq;
use nexxrust::protocols::contact_link::{PeerLink, TAG_CONN_REQ};

const CA: &str = include_str!("../../assets/smp6-5223-chain.pem");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).cloned().unwrap_or_else(|| "smp6.simplex.im:5223".into());
    let (h, p) = host.split_once(':').unwrap();
    let port: u16 = p.parse().unwrap();
    let key_hash = crypto::sha256_raw(CA.as_bytes());
    let wait = std::time::Duration::from_secs(40);

    let seed_a = crypto::sha256_raw(b"nexx link smoke alice");
    let seed_b = crypto::sha256_raw(b"nexx link smoke bob");
    let mut alice = PeerLink::new(h, port, &seed_a, Some(CA)).expect("alice new");
    let mut bob = PeerLink::new(h, port, &seed_b, Some(CA)).expect("bob new");
    println!("OK NEW+SUB alice rcv={} bob rcv={}", crypto::hex_encode(&alice.ids.rcv_id), crypto::hex_encode(&bob.ids.rcv_id));

    // Alice → инвайт
    let uri = alice.invite_uri(h, port, &key_hash);
    println!("OK INVITE uri {} байт", uri.len());

    // Bob принимает: шлёт свой connReq Alice
    let (inv_snd, _inv_dh) = bob.accept_invite(&uri, h, port, &key_hash, wait).expect("bob accept");
    println!("OK BOB sent connReq to alice snd={}", crypto::hex_encode(&inv_snd));

    // Alice: recv_e2e = alice.dh × bob.eph_pub — bob.eph_pub пока неизвестен Alice.
    // В PeerLink эфемерный ключ передаётся в send_message(dh_pub) и попадает в envelope;
    // для приёма нам нужен secret = rcv_dh × snd_eph. Забираем snd_eph из первого сообщения:
    // временно принимаем «вручную» — но decrypt_client_msg требует secret заранее.
    // Поэтому здесь используем подход invite_flow: устанавливаем recv_e2e после того,
    // как знаем bob.eph. Для этого расширим: прочитаем raw MSG и извлечём snd pub.
    let (_mid, bob_eph_pub, bob_req_bytes) = alice.recv_raw(wait).expect("alice recv bob connReq");
    assert_eq!(bob_req_bytes[0], TAG_CONN_REQ, "ожидался connReq");
    let bob_req = connreq::decode_conn_req(&bob_req_bytes[1..]).expect("decode bob connReq");
    println!("OK ALICE got BOB connReq snd={}", crypto::hex_encode(&bob_req.queues[0].sender_id));

    // Ключи обеих сторон
    alice.install_peer(&bob_req, &bob_eph_pub).expect("alice install");
    // bob.peer — alice из инвайта; эфемерный pub ALICE для recv_e2e = bob.dh × alice.eph
    let alice_eph_pub = *x25519_dalek::PublicKey::from(&alice.eph).as_bytes();
    let parsed = connreq::decode_invite_uri(&uri).unwrap();
    bob.install_peer(&parsed, &alice_eph_pub).expect("bob install");

    // Alice → Bob чат
    alice.send_chat("NeXX link: hello Bob!").expect("alice send");
    println!("OK ALICE sent chat");
    let msgs = bob.poll_chat(std::time::Duration::from_secs(30)).expect("bob poll");
    assert!(msgs.iter().any(|m| m.contains("hello Bob")), "bob не получил: {msgs:?}");
    println!("OK BOB recv: {:?}", msgs);

    // Bob → Alice чат
    bob.send_chat("NeXX link: hi Alice, both ways!").expect("bob send");
    println!("OK BOB sent chat");
    let msgs = alice.poll_chat(std::time::Duration::from_secs(30)).expect("alice poll");
    assert!(msgs.iter().any(|m| m.contains("hi Alice")), "alice не получила: {msgs:?}");
    println!("OK ALICE recv: {:?}", msgs);

    alice.close();
    bob.close();
    println!("OK CONTACT LINK SMOKE OK — 1-1 чат в обе стороны через {host}");
}

