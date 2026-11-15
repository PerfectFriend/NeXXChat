//! INVITE FLOW: установление 1-1 контакта между двумя клиентами NeXX через
//! публичный SMP-релей — полный цикл:
//!   Alice: NEW+SUB → connReqData → URI `nexx://link#/...`
//!   Bob:   парсит URI → NEW+SUB (своя очередь) → шлёт свой connReqData в очередь Alice
//!   Alice: читает connReq Bob → шлёт Bob подтверждение (текст) в его очередь
//!   Bob:   читает подтверждение → контакт установлен, чат в обе стороны
//! Запуск: NEXX_TLS=openssl invite_flow smp6.simplex.im:5223
use nexxrust::crypto;
use nexxrust::keytree;
use nexxrust::protocols::connreq::{self, ConnReqData, SmpQueueUri};
use nexxrust::protocols::smp;
use nexxrust::protocols::smp_client::SmpClient;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

const CA: &str = include_str!("/home/thomas/.hermes/cache/scratch/smp6-5223-chain.pem");

/// Тело agent-сообщения «contact request»: 'C' + connReqData.
const TAG_CONN_REQ: u8 = b'C';

struct Peer {
    client: SmpClient,
    auth: ed25519_dalek::SigningKey,
    dh: StaticSecret,
    ids: smp::QueueIds,
    eph: StaticSecret,
    eph_x: Vec<u8>,
    /// e2e secret с собеседником (после обмена connReq) и его эфемерный ключ для приёма.
    peer_e2e: Option<[u8; 32]>,
    peer_eph_x: Option<Vec<u8>>,
    /// e2e secret для ПРИЕМА от собеседника (rcv_dh_secret × peer_eph_pub).
    recv_e2e: Option<[u8; 32]>,
}

fn make_peer(h: &str, port: u16, seed_tag: &str) -> Peer {
    let seed = crypto::sha256_raw(format!("nexx invite {seed_tag}").as_bytes());
    let auth = ed25519_dalek::SigningKey::from_bytes(&keytree::derive_path_ed25519(&seed, "m/0'/0'/0'").unwrap().private);
    let dh = StaticSecret::from(keytree::derive_path_ed25519(&seed, "m/0'/0'/1'").unwrap().private);
    let mut client = SmpClient::connect_openssl_with_ca(h, port, Some(CA)).expect("connect");
    let ids = client.create_queue(&smp::RecipientKeys { auth_signing: auth.clone(), dh_secret: dh.clone() }).expect("NEW");
    client.subscribe(&ids.rcv_id, &auth).expect("SUB");
    let eph_b: [u8; 32] = crypto::random_bytes(32).try_into().unwrap();
    let eph = StaticSecret::from(eph_b);
    let eph_x = smp::x25519_x509(X25519Public::from(&eph).as_bytes());
    Peer { client, auth, dh, ids, eph, eph_x, peer_e2e: None, peer_eph_x: None, recv_e2e: None }
}

impl Peer {
    fn srv_secret(&self) -> [u8; 32] {
        self.dh.diffie_hellman(&X25519Public::from(smp::parse_x25519_x509(&self.ids.srv_dh_x509).unwrap())).to_bytes()
    }
    /// connReqData с нашей очередью для раздачи собеседнику.
    fn conn_req(&self, host: &str, port: u16) -> ConnReqData {
        ConnReqData {
            agent_v_min: connreq::AGENT_V_MIN,
            agent_v_max: connreq::AGENT_V_MAX,
            queues: vec![SmpQueueUri {
                smp_v_min: self.client.version,
                smp_v_max: self.client.version,
                host: host.to_string(),
                port,
                server_key_hash: crypto::sha256_raw(CA.as_bytes()).to_vec(),
                sender_id: self.ids.snd_id.clone(),
                dh_x509: smp::x25519_x509(X25519Public::from(&self.dh).as_bytes()),
                queue_mode: b'M',
            }],
            client_data: Some(b"nexx-invite".to_vec()),
        }
    }
    /// Шлёт body ('_' + agentMsg) в очередь собеседника (snd_id + его rcv dh x509).
    fn send_to_peer(&mut self, peer_snd_id: &[u8], peer_rcv_dh_x509: &[u8], agent_body: &[u8]) {
        let e2e = self.eph.diffie_hellman(&X25519Public::from(smp::parse_x25519_x509(peer_rcv_dh_x509).unwrap()));
        let mut body = vec![b'_'];
        body.extend_from_slice(agent_body);
        self.client.send_message(peer_snd_id, e2e.as_bytes(), Some(&self.eph_x), &body, b"").expect("SEND to peer");
    }
    /// Принимает одно сообщение из своей очереди (с ретраями poll), возвращает (msg_id, agent_body).
    fn recv_agent_msg(&mut self) -> (Vec<u8>, Vec<u8>) {
        self.client.set_read_timeout(Some(std::time::Duration::from_millis(300)));
        for _ in 0..80 {
            for cmd in self.client.take_pending() {
                if let Ok(m) = smp::parse_msg(&cmd) {
                    let rcv = smp::decrypt_rcv_msg(&self.srv_secret(), &m.msg_id, &m.body).expect("srv decrypt");
                    let (_ph, plain) = smp::decrypt_client_msg(self.recv_e2e.as_ref().expect("recv e2e"), &rcv.envelope).expect("e2e decrypt");
                    let (_ph2, body) = smp::parse_priv_header(&plain).expect("priv header");
                    self.client.ack(&self.ids.rcv_id, &self.auth, &m.msg_id).expect("ACK");
                    return (m.msg_id, body.to_vec());
                }
            }
            match self.client.recv_transmissions() {
                Ok(items) => {
                    for (_a, _c, _e, cmd) in items {
                        if let Ok(m) = smp::parse_msg(&cmd) {
                            let rcv = smp::decrypt_rcv_msg(&self.srv_secret(), &m.msg_id, &m.body).expect("srv decrypt");
                            let (_ph, plain) = smp::decrypt_client_msg(self.recv_e2e.as_ref().expect("recv e2e"), &rcv.envelope).expect("e2e decrypt");
                            let (_ph2, body) = smp::parse_priv_header(&plain).expect("priv header");
                            self.client.ack(&self.ids.rcv_id, &self.auth, &m.msg_id).expect("ACK");
                            return (m.msg_id, body.to_vec());
                        }
                    }
                }
                Err(e) if e.contains("Resource temporarily unavailable") || e.contains("timed out") => {}
                Err(e) => panic!("recv: {e}"),
            }
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        panic!("FAIL: нет входящего сообщения за 80 итераций");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).cloned().unwrap_or_else(|| "smp6.simplex.im:5223".into());
    let (h, p) = host.split_once(':').unwrap();
    let port: u16 = p.parse().unwrap();

    // === Alice создаёт инвайт ===
    let mut alice = make_peer(h, port, "alice");
    let alice_req = alice.conn_req(h, port);
    let uri = connreq::encode_invite_uri(&alice_req);
    println!("OK ALICE NEW+SUB rcv={}", crypto::hex_encode(&alice.ids.rcv_id));
    println!("OK ALICE INVITE URI nexx://link#/{}... ({} байт connReq)", &uri[16..26], connreq::encode_conn_req(&alice_req).len());

    // === Bob принимает инвайт ===
    let parsed = connreq::decode_invite_uri(&uri).expect("parse invite uri");
    assert_eq!(parsed, alice_req, "roundtrip URI == connReqData");
    println!("OK BOB parsed invite: host={} port={} snd={}", parsed.queues[0].host, parsed.queues[0].port, crypto::hex_encode(&parsed.queues[0].sender_id));

    let mut bob = make_peer(h, port, "bob");
    println!("OK BOB NEW+SUB rcv={}", crypto::hex_encode(&bob.ids.rcv_id));

    // e2e Bob→Alice: эфемерный Bob × rcv-dh Alice из connReq
    let alice_rcv_dh_x = parsed.queues[0].dh_x509.clone();
    let bob_e2e_to_alice = bob.eph.diffie_hellman(&X25519Public::from(smp::parse_x25519_x509(&alice_rcv_dh_x).unwrap())).to_bytes();
    bob.peer_e2e = Some(bob_e2e_to_alice); // bob шлёт этим; alice примет своим e2e с bob.eph_x — установим ниже

    // Bob шлёт свой connReq в очередь Alice
    let bob_req = bob.conn_req(h, port);
    let mut agent_body = vec![TAG_CONN_REQ];
    agent_body.extend_from_slice(&connreq::encode_conn_req(&bob_req));
    bob.send_to_peer(&parsed.queues[0].sender_id, &alice_rcv_dh_x, &agent_body);
    println!("OK BOB sent connReq to Alice queue");

    // Alice примет: её e2e с Bob = alice.eph? Нет — Bob шифровал на alice rcv-dh эфемерным bob.eph.
    // decrypt_client_msg нужен secret = rcv_dh_secret × sender_eph_pub = alice.dh × bob.eph_pub.
    alice.recv_e2e = Some(alice.dh.diffie_hellman(&X25519Public::from(&bob.eph)).to_bytes());
    let (_mid, body) = alice.recv_agent_msg();
    assert_eq!(body[0], TAG_CONN_REQ, "ожидался connReq");
    let bob_req_back = connreq::decode_conn_req(&body[1..]).expect("decode bob connReq");
    assert_eq!(bob_req_back, bob_req);
    println!("OK ALICE received BOB connReq snd={}", crypto::hex_encode(&bob_req_back.queues[0].sender_id));

    // e2e Alice→Bob
    let bob_rcv_dh_x = bob_req_back.queues[0].dh_x509.clone();
    alice.peer_e2e = Some(alice.eph.diffie_hellman(&X25519Public::from(smp::parse_x25519_x509(&bob_rcv_dh_x).unwrap())).to_bytes());
    // Bob примет: secret = bob.dh × alice.eph_pub
    bob.recv_e2e = Some(bob.dh.diffie_hellman(&X25519Public::from(&alice.eph)).to_bytes());

    // Alice → Bob: подтверждение контакта (обычный чат-текст)
    let hello = b"NeXX: contact accepted, 1-1 link established";
    let mut body = vec![b'_'];
    body.extend_from_slice(hello);
    alice.send_to_peer(&bob_req_back.queues[0].sender_id, &bob_rcv_dh_x, hello);
    println!("OK ALICE sent accept to BOB queue");

    let (_mid, body) = bob.recv_agent_msg();
    let text = String::from_utf8_lossy(&body).to_string();
    assert_eq!(text.as_bytes(), hello);
    println!("OK BOB received accept: {text:?}");

    // Bob → Alice: ответ в обратную сторону
    let reply = b"NeXX: reply - link works both ways";
    bob.send_to_peer(&alice.ids.snd_id, &smp::x25519_x509(X25519Public::from(&alice.dh).as_bytes()), reply);
    let (_mid, body) = alice.recv_agent_msg();
    let text2 = String::from_utf8_lossy(&body).to_string();
    assert_eq!(text2.as_bytes(), reply);
    println!("OK ALICE received reply: {text2:?}");

    alice.client.delete_queue(&alice.ids.rcv_id, &alice.auth).expect("DEL alice");
    bob.client.delete_queue(&bob.ids.rcv_id, &bob.auth).expect("DEL bob");
    println!("OK INVITE FLOW OK — 1-1 контакт через публичный релей в обе стороны");
}
