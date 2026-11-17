//! 1-1 contact link поверх публичного SMP-релея — библиотечная версия invite_flow.
//!
//! Цикл: Alice делает инвайт (connReq URI) → Bob шлёт свой connReq в очередь Alice
//! → Alice отвечает connReq'ом Bob → обе стороны получают peer_snd_id и E2E-ключи,
//! чат идёт в обе стороны. Поверх проверенного agent/SMP-протокола (см. bin/invite_flow.rs).
use crate::crypto;
use crate::keytree;
use crate::protocols::connreq::{self, ConnReqData, SmpQueueUri};
use crate::protocols::smp;
use crate::protocols::smp_client::SmpClient;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// Тело agent-сообщения «contact request»: 'C' + connReqData.
pub const TAG_CONN_REQ: u8 = b'C';

/// Разобранное входящее сообщение: (msg_id, эфемерный pub отправителя, body).
pub type RawMsg = (Vec<u8>, [u8; 32], Vec<u8>);

/// One side of a 1-1 link: своя очередь + (после handshake) данные собеседника.
pub struct PeerLink {
    pub client: SmpClient,
    pub auth: ed25519_dalek::SigningKey,
    pub dh: StaticSecret,
    pub ids: smp::QueueIds,
    pub eph: StaticSecret,
    pub eph_x: Vec<u8>,
    /// e2e secret для ОТПРАВКИ собеседнику (eph × peer_rcv_dh_pub).
    pub send_e2e: Option<[u8; 32]>,
    /// e2e secret для ПРИЕМА от собеседника (my_dh × peer_eph_pub) — приходит в envelope.
    pub recv_e2e: Option<[u8; 32]>,
    /// peer senderId (куда шлём) — из connReq собеседника.
    pub peer_snd_id: Vec<u8>,
    /// peer rcv DH (x509) — из connReq собеседника.
    pub peer_rcv_dh_x: Vec<u8>,
}

impl PeerLink {
    /// Создаёт сторону линка: NEW + SUB своей очереди на реле.
    pub fn new(host: &str, port: u16, seed: &[u8], ca_pem: Option<&str>) -> Result<Self, String> {
        let auth = ed25519_dalek::SigningKey::from_bytes(
            &keytree::derive_path_ed25519(seed, "m/0'/0'/0'").ok_or("keytree auth")?.private,
        );
        let dh = StaticSecret::from(
            keytree::derive_path_ed25519(seed, "m/0'/0'/1'").ok_or("keytree dh")?.private,
        );
        let mut client = match ca_pem {
            Some(ca) => SmpClient::connect_openssl_with_ca(host, port, Some(ca)),
            None => SmpClient::connect(host, port),
        }
        .map_err(|e| format!("connect {host}:{port}: {e}"))?;
        let ids = client
            .create_queue(&smp::RecipientKeys { auth_signing: auth.clone(), dh_secret: dh.clone() })
            .map_err(|e| format!("NEW: {e}"))?;
        client.subscribe(&ids.rcv_id, &auth).map_err(|e| format!("SUB: {e}"))?;
        let eph_b: [u8; 32] = crypto::random_bytes(32).try_into().map_err(|_| "rng")?;
        let eph = StaticSecret::from(eph_b);
        let eph_x = smp::x25519_x509(X25519Public::from(&eph).as_bytes());
        Ok(PeerLink {
            client,
            auth,
            dh,
            ids,
            eph,
            eph_x,
            send_e2e: None,
            recv_e2e: None,
            peer_snd_id: Vec::new(),
            peer_rcv_dh_x: Vec::new(),
        })
    }

    fn srv_secret(&self) -> [u8; 32] {
        self.dh
            .diffie_hellman(&X25519Public::from(
                smp::parse_x25519_x509(&self.ids.srv_dh_x509).ok_or("bad srv dh").unwrap(),
            ))
            .to_bytes()
    }

    /// connReqData с нашей очередью — для раздачи инвайтом.
    pub fn conn_req(&self, host: &str, port: u16, server_key_hash: &[u8]) -> ConnReqData {
        ConnReqData {
            agent_v_min: connreq::AGENT_V_MIN,
            agent_v_max: connreq::AGENT_V_MAX,
            queues: vec![SmpQueueUri {
                smp_v_min: self.client.version,
                smp_v_max: self.client.version,
                host: host.to_string(),
                port,
                server_key_hash: server_key_hash.to_vec(),
                sender_id: self.ids.snd_id.clone(),
                dh_x509: smp::x25519_x509(X25519Public::from(&self.dh).as_bytes()),
                queue_mode: b'M',
            }],
            client_data: Some(b"nexx-invite".to_vec()),
        }
    }

    /// Инвайт-URI для раздачи собеседнику.
    pub fn invite_uri(&self, host: &str, port: u16, server_key_hash: &[u8]) -> String {
        connreq::encode_invite_uri(&self.conn_req(host, port, server_key_hash))
    }

    /// Шлёт agent body ('_' + agentMsg) в очередь собеседника.
    pub fn send_to_peer(&mut self, peer_snd_id: &[u8], peer_rcv_dh_x: &[u8], agent_body: &[u8]) -> Result<(), String> {
        let e2e = self
            .eph
            .diffie_hellman(&X25519Public::from(
                smp::parse_x25519_x509(peer_rcv_dh_x).ok_or("bad peer dh")?,
            ));
        let mut body = vec![b'_'];
        body.extend_from_slice(agent_body);
        self.client
            .send_message(peer_snd_id, e2e.as_bytes(), Some(&self.eph_x), &body, b"")
            .map_err(|e| format!("SEND: {e}"))
    }

    /// Принимает одно сообщение из своей очереди (неблокирующий poll с ретраями).
    /// `timeout_total` — общий бюджет ожидания. Возвращает (msg_id, agent_body).
    pub fn recv_agent_msg(&mut self, timeout_total: std::time::Duration) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.client.set_read_timeout(Some(std::time::Duration::from_millis(300)));
        let deadline = std::time::Instant::now() + timeout_total;
        loop {
            for cmd in self.client.take_pending() {
                if let Ok(m) = smp::parse_msg(&cmd) {
                    let rcv = smp::decrypt_rcv_msg(&self.srv_secret(), &m.msg_id, &m.body)
                        .map_err(|e| format!("srv decrypt: {e}"))?;
                    let e2e = self.recv_e2e.ok_or("recv_e2e не установлен")?;
                    let (_ph, plain) = smp::decrypt_client_msg(&e2e, &rcv.envelope)
                        .map_err(|e| format!("e2e decrypt: {e}"))?;
                    let (_ph2, body) = smp::parse_priv_header(&plain).map_err(|e| format!("priv header: {e}"))?;
                    self.client.ack(&self.ids.rcv_id, &self.auth, &m.msg_id).map_err(|e| format!("ACK: {e}"))?;
                    return Ok((m.msg_id, body.to_vec()));
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err("таймаут ожидания сообщения".into());
            }
            match self.client.recv_transmissions() {
                Ok(items) => {
                    for (_a, _c, _e, cmd) in items {
                        if let Ok(m) = smp::parse_msg(&cmd) {
                            let rcv = smp::decrypt_rcv_msg(&self.srv_secret(), &m.msg_id, &m.body)
                                .map_err(|e| format!("srv decrypt: {e}"))?;
                            let e2e = self.recv_e2e.ok_or("recv_e2e не установлен")?;
                            let (_ph, plain) = smp::decrypt_client_msg(&e2e, &rcv.envelope)
                                .map_err(|e| format!("e2e decrypt: {e}"))?;
                            let (_ph2, body) = smp::parse_priv_header(&plain).map_err(|e| format!("priv header: {e}"))?;
                            self.client.ack(&self.ids.rcv_id, &self.auth, &m.msg_id).map_err(|e| format!("ACK: {e}"))?;
                            return Ok((m.msg_id, body.to_vec()));
                        }
                    }
                }
                Err(e) if e.contains("Resource temporarily unavailable") || e.contains("timed out") => {}
                Err(e) => return Err(format!("recv: {e}")),
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    /// Bob-side: принимает инвайт, шлёт свой connReq в очередь инвайтера.
    /// Устанавливает send_e2e (к инвайтеру). Возвращает connReq инвайтера (decoded) — нет,
    /// инвайтер ещё не ответил; возвращает (peer_snd_id инвайтера, peer_rcv_dh инвайтера).
    pub fn accept_invite(&mut self, invite_uri: &str, host: &str, port: u16, server_key_hash: &[u8], wait: std::time::Duration) -> Result<(Vec<u8>, Vec<u8>), String> {
        let parsed = connreq::decode_invite_uri(invite_uri)?;
        let q = parsed.queues.first().ok_or("в ссылке нет очередей")?;
        let inviter_snd = q.sender_id.clone();
        let inviter_rcv_dh = q.dh_x509.clone();
        // e2e к инвайтеру
        self.send_e2e = Some(
            self.eph
                .diffie_hellman(&X25519Public::from(
                    smp::parse_x25519_x509(&inviter_rcv_dh).ok_or("bad inviter dh")?,
                ))
                .to_bytes(),
        );
        // шлём свой connReq инвайтеру
        let my_req = self.conn_req(host, port, server_key_hash);
        let mut agent_body = vec![TAG_CONN_REQ];
        agent_body.extend_from_slice(&connreq::encode_conn_req(&my_req));
        self.send_to_peer(&inviter_snd, &inviter_rcv_dh, &agent_body)?;
        // ждём ответного connReq инвайтера: recv_e2e = my_dh × inviter_eph_pub —
        // но эфемерный ключ инвайтера приходит внутри envelope; decrypt_client_msg
        // для приёма нуждается в secret = rcv_dh × snd_eph. Мы знаем свой rcv dh,
        // эфемерный ключ отправителя — в открытом виде в SMP envelope? В нашей
        // реализации send_message передаёт dh_pub отдельным параметром, и
        // decrypt_client_msg использует envelope.snd_pub. Поэтому recv_e2e
        // вычисляем как dh × inviter_eph — но мы его не знаем до первого сообщения.
        // Решение: inviter шлёт connReq первым, и его эфемерный pub мы можем взять
        // из... на практике invite_flow устанавливал recv_e2e вручную. Здесь —
        // двухфазно: сначала принимаем с "wildcard" нельзя. Поэтому accept_invite
        // возвращает управление после отправки, а install_peer_eph вызывается
        // после того, как известен эфемерный ключ инвайтера (из первого recv).
        let _ = wait;
        Ok((inviter_snd, inviter_rcv_dh))
    }

    /// Устанавливает ключи собеседника после обмена connReq (обе стороны).
    /// peer_req — connReq собеседника; my_eph_of_peer — эфемерный pub собеседника (из его первого сообщения, если нужно).
    pub fn install_peer(&mut self, peer_req: &ConnReqData, peer_eph_pub: &[u8; 32]) -> Result<(), String> {
        let q = peer_req.queues.first().ok_or("нет очередей у peer")?;
        self.peer_snd_id = q.sender_id.clone();
        self.peer_rcv_dh_x = q.dh_x509.clone();
        self.send_e2e = Some(
            self.eph
                .diffie_hellman(&X25519Public::from(
                    smp::parse_x25519_x509(&q.dh_x509).ok_or("bad peer dh")?,
                ))
                .to_bytes(),
        );
        self.recv_e2e = Some(
            self.dh
                .diffie_hellman(&X25519Public::from(*peer_eph_pub))
                .to_bytes(),
        );
        Ok(())
    }

    /// Шлёт чат-текст собеседнику (уже после install_peer).
    pub fn send_chat(&mut self, text: &str) -> Result<(), String> {
        let snd = if self.peer_snd_id.is_empty() { return Err("peer не установлен".into()); } else { &self.peer_snd_id };
        let e2e = self.send_e2e.ok_or("send_e2e не установлен")?;
        let mut body = vec![b'_'];
        body.extend_from_slice(text.as_bytes());
        self.client
            .send_message(snd, &e2e, Some(&self.eph_x), &body, b"")
            .map_err(|e| format!("SEND chat: {e}"))
    }

    /// Poll своей очереди: возвращает все входящие чат-тексты (без блокировки дольше timeout_total).
    pub fn poll_chat(&mut self, timeout_total: std::time::Duration) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        // сначала pending
        let mut cmds: Vec<Vec<u8>> = self.client.take_pending();
        if let Ok(items) = self.client.recv_transmissions() {
            for (_a, _c, _e, cmd) in items { cmds.push(cmd); }
        }
        let deadline = std::time::Instant::now() + timeout_total;
        loop {
            let mut progressed = false;
            for cmd in cmds.drain(..) {
                if let Ok(m) = smp::parse_msg(&cmd) {
                    progressed = true;
                    let rcv = match smp::decrypt_rcv_msg(&self.srv_secret(), &m.msg_id, &m.body) {
                        Ok(r) => r,
                        Err(_) => { let _ = self.client.ack(&self.ids.rcv_id, &self.auth, &m.msg_id); continue; }
                    };
                    if let Some(e2e) = self.recv_e2e {
                        if let Ok((_ph, plain)) = smp::decrypt_client_msg(&e2e, &rcv.envelope) {
                            if let Ok((_ph2, body)) = smp::parse_priv_header(&plain) {
                                out.push(String::from_utf8_lossy(body).to_string());
                            }
                        }
                    }
                    let _ = self.client.ack(&self.ids.rcv_id, &self.auth, &m.msg_id);
                }
            }
            if !progressed || std::time::Instant::now() >= deadline {
                // один дополнительный неблокирующий poll если времени осталось
                if std::time::Instant::now() < deadline {
                    match self.client.recv_transmissions() {
                        Ok(items) => { for (_a, _c, _e, cmd) in items { cmds.push(cmd); } }
                        Err(e) if e.contains("Resource temporarily unavailable") || e.contains("timed out") => {}
                        Err(e) => return Err(format!("recv: {e}")),
                    }
                    if !cmds.is_empty() { continue; }
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    continue;
                }
                break;
            }
        }
        Ok(out)
    }

    pub fn close(&mut self) {
        let _ = self.client.delete_queue(&self.ids.rcv_id, &self.auth);
    }

    /// Секрет srv-слоя (для ручного парсинга входящих).
    pub fn srv_secret_pub(&self) -> [u8; 32] {
        self.srv_secret()
    }

    /// Парсит одно входящее MSG «вручную»: (msg_id, snd_eph_pub, body),
    /// эфемерный ключ отправителя извлекается из envelope (SPKI-префикс X25519).
    pub fn parse_incoming_raw(&mut self, cmd: &[u8]) -> Option<RawMsg> {
        let m = smp::parse_msg(cmd).ok()?;
        let srv = self.srv_secret();
        let rcv = smp::decrypt_rcv_msg(&srv, &m.msg_id, &m.body).ok()?;
        let snd_pub = extract_snd_pub(&rcv.envelope)?;
        let e2e = self.dh.diffie_hellman(&X25519Public::from(snd_pub)).to_bytes();
        let (_ph, plain) = smp::decrypt_client_msg(&e2e, &rcv.envelope).ok()?;
        let (_ph2, body) = smp::parse_priv_header(&plain).ok()?;
        Some((m.msg_id, snd_pub, body.to_vec()))
    }

    /// Принимает одно сообщение с извлечением эфемерного ключа отправителя (для handshake).
    pub fn recv_raw(&mut self, timeout_total: std::time::Duration) -> Result<RawMsg, String> {
        self.client.set_read_timeout(Some(std::time::Duration::from_millis(300)));
        let deadline = std::time::Instant::now() + timeout_total;
        loop {
            for cmd in self.client.take_pending() {
                if let Some(t) = self.parse_incoming_raw(&cmd) {
                    let _ = self.client.ack(&self.ids.rcv_id, &self.auth, &t.0);
                    return Ok(t);
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err("таймаут".into());
            }
            match self.client.recv_transmissions() {
                Ok(items) => {
                    for (_a, _c, _e, cmd) in items {
                        if let Some(t) = self.parse_incoming_raw(&cmd) {
                            let _ = self.client.ack(&self.ids.rcv_id, &self.auth, &t.0);
                            return Ok(t);
                        }
                    }
                }
                Err(e) if e.contains("temporarily") || e.contains("timed out") => {}
                Err(e) => return Err(format!("recv: {e}")),
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
}

/// Извлекает X25519 snd pub из SMP envelope по SPKI-префиксу.
pub fn extract_snd_pub(envelope: &[u8]) -> Option<[u8; 32]> {
    const PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00];
    for i in 0..envelope.len().saturating_sub(44) {
        if envelope[i..i + 12] == PREFIX {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&envelope[i + 12..i + 44]);
            return Some(pk);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_req_uri_roundtrip_through_link_api() {
        // без сети: проверяем, что conn_req/invite_uri кодируются и парсятся обратно
        let seed = crypto::sha256_raw(b"contact_link test seed");
        // PeerLink::new требует сеть — поэтому тестируем только кодеки через connreq
        let req = ConnReqData {
            agent_v_min: connreq::AGENT_V_MIN,
            agent_v_max: connreq::AGENT_V_MAX,
            queues: vec![SmpQueueUri {
                smp_v_min: 20,
                smp_v_max: 20,
                host: "smp6.simplex.im".into(),
                port: 5223,
                server_key_hash: crypto::sha256_raw(b"ca"),
                sender_id: vec![7u8; 16],
                dh_x509: smp::x25519_x509(X25519Public::from(&StaticSecret::from([9u8; 32])).as_bytes()),
                queue_mode: b'M',
            }],
            client_data: Some(b"nexx-invite".to_vec()),
        };
        let uri = connreq::encode_invite_uri(&req);
        let back = connreq::decode_invite_uri(&uri).unwrap();
        assert_eq!(req, back);
        let _ = seed;
    }

    #[test]
    fn tag_conn_req_constant() {
        assert_eq!(TAG_CONN_REQ, b'C');
    }
}
