//! UI приложения NeXX: онбординг (BIP39) → чат (SMP live) + кошелёк + флот нод.
//! Вся криптография — напрямую из nexxrust (rlib), никакого JNI.
//! Раскладка как в Telegram: слева список чатов, справа переписка, ввод снизу.

use nexxrust::{bip39, control, crypto, keytree};
use nexxrust::protocols::queue_store;
use nexxrust::protocols::smp;
use nexxrust::protocols::smp_client::SmpClient;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// CA-цепочка публичных SMP-релеев перенесена в `servers.rs` (аудит M6).

/// Каталог данных приложения (Android private dir / XDG fallback).
fn data_dir() -> String {
    std::env::var("ANDROID_APP_PRIVATE_DIR")
        .or_else(|_| std::env::var("XDG_DATA_HOME").map(|d| format!("{d}/nexx")))
        .unwrap_or_else(|_| "/data/data/chat.nexx.app/files".to_string())
}

/// Достаёт эфемерный x25519-публичный ключ отправителя из SMP-конверта
/// (формат: u16 version, u8 tag '1', u16 len, DER x509) — нужен для E2E DH
/// до вызова decrypt_client_msg.
fn env_eph(envelope: &[u8]) -> Option<[u8; 32]> {
    if envelope.len() < 5 || envelope[2] != b'1' {
        return None;
    }
    let len = u16::from_be_bytes([envelope[3], envelope[4]]) as usize;
    let der = envelope.get(5..5 + len)?;
    nexxrust::protocols::smp::parse_x25519_x509(der)
}

/// Путь зашифрованного хранилища очередей (стандартная директория данных приложения).
fn queue_store_path() -> String {
    format!("{}/queues.bin", data_dir())
}

enum WorkerCmd {
    Send(String),
    Quit,
}

// ===== 1-1 contact link (Этап 2.2): отдельный воркер с PeerLink =====
enum LinkCmd {
    /// Принять инвайт-ссылку: шлём свой connReq в очередь инвайтера.
    AcceptInvite(String),
    Send(String),
    Quit,
}

enum LinkEvent {
    Status(String),
    MyInvite(String),   // наш инвайт-URI для раздачи
    PeerReady(String),  // имя/id установленного peer (после handshake)
    Incoming(String),
    SentOk,
    Err(String),
}

/// Воркер 1-1 линка: своя очередь (NEW+SUB), инвайт-URI, приём connReq от входящих
/// и ответный connReq (handshake), приём/отправка чат-сообщений активному peer.
fn link_worker(
    host: String,
    port: u16,
    ca_pem: &'static str,
    seed: Vec<u8>,
    ev: Sender<LinkEvent>,
    cmd: Receiver<LinkCmd>,
) {
    use nexxrust::protocols::connreq;
    use nexxrust::protocols::contact_link::{PeerLink, TAG_CONN_REQ};
    let say = |e: LinkEvent| { let _ = ev.send(e); };
    let mut link = match PeerLink::new(&host, port, &seed, Some(ca_pem)) {
        Ok(l) => l,
        Err(e) => { say(LinkEvent::Err(format!("link NEW: {e}"))); return; }
    };
    let key_hash = crypto::sha256_raw(ca_pem.as_bytes());
    let uri = link.invite_uri(&host, port, &key_hash);
    say(LinkEvent::MyInvite(uri));
    say(LinkEvent::Status(format!("очередь готова, жду инвайты/сообщения на {}", &host)));

    loop {
        // команды UI
        while let Ok(c) = cmd.try_recv() {
            match c {
                LinkCmd::Quit => { link.close(); return; }
                LinkCmd::AcceptInvite(uri) => {
                    match link.accept_invite(&uri, &host, port, &key_hash, Duration::from_secs(5)) {
                        Ok((snd, _dh)) => say(LinkEvent::Status(format!("connReq отправлен инвайтеру snd={}…", crypto::hex_encode(&snd)[..16].to_string()))),
                        Err(e) => say(LinkEvent::Err(format!("accept: {e}"))),
                    }
                }
                LinkCmd::Send(text) => match link.send_chat(&text) {
                    Ok(()) => { say(LinkEvent::SentOk); }
                    Err(e) => say(LinkEvent::Err(format!("send: {e}"))),
                },
            }
        }
        // входящие: короткий poll
        match link.recv_raw(Duration::from_millis(700)) {
            Ok((_mid, snd_pub, body)) => {
                if body.first() == Some(&TAG_CONN_REQ) {
                    match connreq::decode_conn_req(&body[1..]) {
                        Ok(req) => {
                            let peer_snd = req.queues.first().map(|q| crypto::hex_encode(&q.sender_id)).unwrap_or_default();
                            if let Err(e) = link.install_peer(&req, &snd_pub) {
                                say(LinkEvent::Err(format!("install peer: {e}")));
                                continue;
                            }
                            // отвечаем своим connReq — handshake завершён с нашей стороны
                            let my_req = link.conn_req(&host, port, &key_hash);
                            let mut ab = vec![TAG_CONN_REQ];
                            ab.extend_from_slice(&connreq::encode_conn_req(&my_req));
                            let ps = link.peer_snd_id.clone();
                            let pdh = link.peer_rcv_dh_x.clone();
                            if let Err(e) = link.send_to_peer(&ps, &pdh, &ab) {
                                say(LinkEvent::Err(format!("reply connReq: {e}")));
                            } else {
                                say(LinkEvent::PeerReady(peer_snd[..16.min(peer_snd.len())].to_string()));
                            }
                        }
                        Err(e) => say(LinkEvent::Err(format!("decode connReq: {e}"))),
                    }
                } else {
                    say(LinkEvent::Incoming(String::from_utf8_lossy(&body).to_string()));
                }
            }
            Err(e) if e.contains("таймаут") => {}
            Err(e) => say(LinkEvent::Err(format!("recv: {e}"))),
        }
    }
}

// ===== Файлы (Этап 3.2): XFTP chunked через библиотеку xftp_file =====
enum FileCmd {
    Upload(String),      // путь к файлу
    Download(String),    // link nexx://file#/…
    Quit,
}
enum FileEvent {
    Status(String),
    Link(String),
    Saved(String),
    Err(String),
}

fn file_worker(ev: Sender<FileEvent>, cmd: Receiver<FileCmd>) {
    use nexxrust::protocols::xftp_file;
    let say = |e: FileEvent| { let _ = ev.send(e); };
    let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(r) => r,
        Err(e) => { say(FileEvent::Err(format!("tokio rt: {e}"))); return; }
    };
    while let Ok(c) = cmd.recv() {
        match c {
            FileCmd::Quit => break,
            FileCmd::Upload(path) => {
                say(FileEvent::Status(format!("читаю {path}…")));
                let data = match std::fs::read(&path) {
                    Ok(d) => d,
                    Err(e) => { say(FileEvent::Err(format!("read: {e}"))); continue; }
                };
                say(FileEvent::Status(format!("upload {}B chunked…", data.len())));
                let r = rt.block_on(xftp_file::upload_file("xftp1.simplex.im", 443, &data));
                match r {
                    Ok(desc) => {
                        let link = desc.encode();
                        say(FileEvent::Status(format!("OK {} chunks", desc.chunks.len())));
                        say(FileEvent::Link(link));
                    }
                    Err(e) => say(FileEvent::Err(format!("upload: {e}"))),
                }
            }
            FileCmd::Download(link) => {
                let r = rt.block_on(async move {
                    let desc = xftp_file::FileDesc::decode(&link)?;
                    let data = xftp_file::download_file(&desc).await?;
                    Ok::<_, String>((desc, data))
                });
                match r {
                    Ok((desc, data)) => {
                        let dir = format!("{}/downloads", data_dir());
                        let _ = std::fs::create_dir_all(&dir);
                        let name = format!("{}/file_{}B.bin", dir, desc.size);
                        match std::fs::write(&name, &data) {
                            Ok(()) => say(FileEvent::Saved(name)),
                            Err(e) => say(FileEvent::Err(format!("write: {e}"))),
                        }
                    }
                    Err(e) => say(FileEvent::Err(format!("download: {e}"))),
                }
            }
        }
    }
}

enum ChatEvent {
    Status(String),
    Ready(String),      // rcv_id hex
    Incoming(String),   // дешифрованное тело
    SentOk,
    Err(String),
}

struct ChatMsg {
    outgoing: bool,
    body: String,
}

fn chat_worker(
    host: String,
    port: u16,
    ca_pem: &'static str,
    seed: Vec<u8>,
    ev: Sender<ChatEvent>,
    cmd: Receiver<WorkerCmd>,
) {
    let say = |e: ChatEvent| { let _ = ev.send(e); };
    // Аудит M3: reconnect с экспоненциальным backoff — соединение не должно
    // умирать навсегда после одного сетевого сбоя.
    let mut backoff = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(30);
    'reconnect: loop {
        say(ChatEvent::Status("TLS connect…".into()));
        let mut client = match SmpClient::connect_openssl_with_ca(&host, port, Some(ca_pem)) {
            Ok(c) => {
                backoff = Duration::from_secs(1); // успех — сброс backoff
                c
            }
            Err(e) => {
                say(ChatEvent::Err(format!("connect: {e} — retry in {:?}", backoff)));
                // Quit во время backoff — выходим сразу
                if let Ok(WorkerCmd::Quit) = cmd.try_recv() {
                    return;
                }
                std::thread::sleep(backoff);
                backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
                continue 'reconnect;
            }
        };
        // Неблокирующий poll: иначе recv_transmissions ждёт до 60 с и команды Send из UI встают в очередь.
        client.set_read_timeout(Some(Duration::from_millis(400)));
        // Аудит H5: у каждой очереди — свой индекс и свои ключи (раньше все очереди
        // использовали m/0'/0'/0' и m/0'/0'/1' — одна идентичность на все серверы).
        // Реквизиты очереди сохраняются в зашифрованное хранилище, чтобы после
        // перезапуска можно было восстановить очередь, а не плодить новые.
        let store_path = std::path::PathBuf::from(queue_store_path());
        let mut store = match queue_store::QueueStore::open(&store_path, &seed) {
            Ok(st) => st,
            Err(e) => {
                say(ChatEvent::Err(format!("queue store: {e}")));
                std::thread::sleep(backoff);
                backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
                continue 'reconnect;
            }
        };
        let label = format!("self@{host}:{port}");
        let index = store.find_by_label(&label).map(|r| r.index).unwrap_or_else(|| store.next_index());
        let keys = match queue_store::derive_queue_keys(&seed, index) {
            Ok(k) => k,
            Err(e) => {
                say(ChatEvent::Err(format!("derive queue keys: {e}")));
                std::thread::sleep(backoff);
                backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
                continue 'reconnect;
            }
        };
        let auth = keys.auth;
        let dh = keys.dh;
        say(ChatEvent::Status("NEW queue…".into()));
        let ids = match client.create_queue(&smp::RecipientKeys { auth_signing: auth.clone(), dh_secret: dh.clone() }) {
            Ok(i) => i,
            Err(e) => {
                say(ChatEvent::Err(format!("NEW: {e} — retry in {:?}", backoff)));
                std::thread::sleep(backoff);
                backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
                continue 'reconnect;
            }
        };
        // Сохраняем реквизиты очереди (шифрованное хранилище) — H5.
        if let Err(e) = store.upsert(queue_store::QueueRecord {
            index,
            rcv_id: crypto::hex_encode(&ids.rcv_id),
            snd_id: crypto::hex_encode(&ids.snd_id),
            label: label.clone(),
            host: host.clone(),
            port,
            srv_dh_pub: crypto::hex_encode(&ids.srv_dh_x509),
        }) {
            say(ChatEvent::Err(format!("queue store save: {e}")));
        }
        let eph_bytes: [u8; 32] = crypto::random_bytes(32).try_into().unwrap();
        let eph = StaticSecret::from(eph_bytes);
        let eph_pub_x509 = smp::x25519_x509(X25519Public::from(&eph).as_bytes());
        let e2e = eph.diffie_hellman(&X25519Public::from(&dh));
        let srv_pub = match smp::parse_x25519_x509(&ids.srv_dh_x509) {
            Some(p) => p,
            None => {
                say(ChatEvent::Err("bad srv dh key".into()));
                std::thread::sleep(backoff);
                backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
                continue 'reconnect;
            }
        };
        let srv = dh.diffie_hellman(&X25519Public::from(srv_pub));
        // SUB — чтобы сервер пушил MSG без ручного GET
        if let Err(e) = client.subscribe(&ids.rcv_id, &auth) {
            say(ChatEvent::Err(format!("SUB: {e}")));
        }
        say(ChatEvent::Ready(crypto::hex_encode(&ids.rcv_id)));

        loop {
            // сначала pending (wait_response складывает входящие MSG туда)
            let mut pending = client.take_pending();
            for c in pending.drain(..) {
                if let Ok(m) = smp::parse_msg(&c) {
                    if let Ok(rcv) = smp::decrypt_rcv_msg(srv.as_bytes(), &m.msg_id, &m.body) {
                        if let Ok((_ph, plain)) = smp::decrypt_client_msg(e2e.as_bytes(), &rcv.envelope) {
                            if let Ok((_ph2, body)) = smp::parse_priv_header(&plain) {
                                say(ChatEvent::Incoming(String::from_utf8_lossy(body).to_string()));
                            }
                        }
                    }
                    let _ = client.ack(&ids.rcv_id, &auth, &m.msg_id);
                }
            }
            // команды из UI
            while let Ok(c) = cmd.try_recv() {
                match c {
                    WorkerCmd::Send(text) => {
                        // ClientMessage = PrivHeader('_') + текст
                        let mut body = vec![b'_'];
                        body.extend_from_slice(text.as_bytes());
                        match client.send_message(&ids.snd_id, e2e.as_bytes(), Some(&eph_pub_x509), &body, b"") {
                            Ok(_) => say(ChatEvent::SentOk),
                            Err(e) => say(ChatEvent::Err(format!("SEND: {e}"))),
                        }
                    }
                    WorkerCmd::Quit => {
                        // Аудит H5: при закрытии удаляем очередь на сервере (DEL),
                        // чтобы на релее не оставались наши идентификаторы.
                        if let Err(e) = client.delete_queue(&ids.rcv_id, &auth) {
                            say(ChatEvent::Err(format!("DEL queue: {e}")));
                        }
                        let _ = store.remove(&label);
                        return;
                    }
                }
            }
            // неблокирующий poll входящих
            match client.recv_transmissions() {
                Ok(items) => {
                    for (_a, _corr, _e, c) in items {
                        if let Ok(m) = smp::parse_msg(&c) {
                            let rcv = smp::decrypt_rcv_msg(srv.as_bytes(), &m.msg_id, &m.body);
                            if let Ok(rcv) = rcv {
                                if let Ok((_ph, plain)) = smp::decrypt_client_msg(e2e.as_bytes(), &rcv.envelope) {
                                    if let Ok((_ph2, body)) = smp::parse_priv_header(&plain) {
                                        say(ChatEvent::Incoming(String::from_utf8_lossy(body).to_string()));
                                    }
                                }
                            }
                            let _ = client.ack(&ids.rcv_id, &auth, &m.msg_id);
                        }
                    }
                }
                Err(e) if e.contains("Resource temporarily unavailable") || e.contains("timed out") => {}
                Err(e) => {
                    // Аудит M3: фатальная ошибка чтения — не выходим, а reconnect с backoff.
                    say(ChatEvent::Err(format!("recv: {e} — reconnect in {:?}", backoff)));
                    std::thread::sleep(backoff);
                    backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
                    continue 'reconnect;
                }
            }
            let mut pending = client.take_pending();
            for c in pending.drain(..) {
                if let Ok(m) = smp::parse_msg(&c) {
                    if let Ok(rcv) = smp::decrypt_rcv_msg(srv.as_bytes(), &m.msg_id, &m.body) {
                        if let Ok((_ph, plain)) = smp::decrypt_client_msg(e2e.as_bytes(), &rcv.envelope) {
                            if let Ok((_ph2, body)) = smp::parse_priv_header(&plain) {
                                say(ChatEvent::Incoming(String::from_utf8_lossy(body).to_string()));
                            }
                        }
                    }
                    let _ = client.ack(&ids.rcv_id, &auth, &m.msg_id);
                }
            }
            std::thread::sleep(Duration::from_millis(800));
        }
    }
}

pub struct NeXXUi {
    phase: Phase,
    mnemonic_input: String,
    mnemonic: Vec<String>,
    show_seed: bool,
    error: String,
    seed_hex: String,
    tab: Tab,
    fleet: Vec<keytree::NodePlan>,
    node_status: Vec<String>,
    node_host: Vec<String>,
    // чат
    chat_host: String,
    chat_port: u16,
    chat_status: String,
    chat_ready: bool,
    chat_rcv: String,
    chat_msgs: Vec<ChatMsg>,
    chat_input: String,
    chat_tx: Option<Sender<WorkerCmd>>,
    chat_rx: Option<Receiver<ChatEvent>>,
    // контакты (Этап 2.2)
    seed: Vec<u8>,
    contacts: Vec<nexxrust::protocols::contact_store::ContactRecord>,
    invite_input: String,
    contact_name: String,
    contacts_status: String,
    // группы (Этап 4.1)
    groups: Vec<nexxrust::protocols::group_store::GroupRecord>,
    group_name: String,
    groups_status: String,
    group_selected: usize,
    group_msg_input: String,
    member_pick: usize,
    // прокси (Этап 4.3): парсинг конфигов, health-check, kill-switch
    proxy_input: String,
    proxy_list: Vec<(String, String)>, // (remarks, json-конфиг)
    proxy_selected: usize,
    proxy_active: bool,
    xray_port: Option<u16>,
    kill_switch: bool,
    proxy_status: String,
    runtime: nexxrust::proxy_runtime::ProxyRuntime,
    // 1-1 линк (Этап 2.2): воркер PeerLink — свой инвайт + handshake + чат с peer
    link_tx: Option<Sender<LinkCmd>>,
    link_rx: Option<Receiver<LinkEvent>>,
    link_status: String,
    my_invite: String,
    link_ready: bool,
    link_peer: String,
    link_msgs: Vec<ChatMsg>,
    link_input: String,
    link_invite_input: String,
    // файлы (Этап 3.2): XFTP chunked upload/download
    file_tx: Option<Sender<FileCmd>>,
    file_rx: Option<Receiver<FileEvent>>,
    file_path: String,
    file_link: String,
    file_recv_link: String,
    file_status: String,
    file_preview: Option<egui::TextureHandle>,
    file_preview_name: String,
}

enum Phase {
    Onboarding,
    Main,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Chats,
    Contacts,
    Groups,
    Proxy,
    Files,
    Wallet,
    Fleet,
}

impl NeXXUi {
    pub fn new() -> Self {
        Self {
            phase: Phase::Onboarding,
            mnemonic_input: String::new(),
            mnemonic: vec![],
            show_seed: false,
            error: String::new(),
            seed_hex: String::new(),
            tab: Tab::Chats,
            fleet: vec![],
            node_status: vec![],
            node_host: vec![],
            chat_host: "smp6.simplex.im".into(),
            chat_port: 5223,
            chat_status: String::new(),
            chat_ready: false,
            chat_rcv: String::new(),
            chat_msgs: vec![],
            chat_input: String::new(),
            chat_tx: None,
            chat_rx: None,
            seed: vec![],
            contacts: vec![],
            invite_input: String::new(),
            contact_name: String::new(),
            contacts_status: String::new(),
            groups: vec![],
            group_name: String::new(),
            groups_status: String::new(),
            group_selected: 0,
            group_msg_input: String::new(),
            member_pick: 0,
            proxy_input: String::new(),
            proxy_list: vec![],
            proxy_selected: 0,
            proxy_active: false,
            xray_port: None,
            kill_switch: true, // по умолчанию kill-switch ВКЛЮЧЕН: без прокси — блок
            proxy_status: String::new(),
            runtime: nexxrust::proxy_runtime::ProxyRuntime::new(true),
            link_tx: None,
            link_rx: None,
            link_status: String::new(),
            my_invite: String::new(),
            link_ready: false,
            link_peer: String::new(),
            link_msgs: vec![],
            link_input: String::new(),
            link_invite_input: String::new(),
            file_tx: None,
            file_rx: None,
            file_path: String::new(),
            file_link: String::new(),
            file_recv_link: String::new(),
            file_status: String::new(),
            file_preview: None,
            file_preview_name: String::new(),
        }
    }

    pub fn ui(&mut self, ctx: &egui::Context) {
        if self.chat_ready {
            ctx.request_repaint_after(Duration::from_millis(400));
        }
        egui::CentralPanel::default().show(ctx, |ui| match self.phase {
            Phase::Onboarding => self.onboarding(ui),
            Phase::Main => self.main(ui, ctx),
        });
    }

    fn onboarding(&mut self, ui: &mut egui::Ui) {
        ui.add_space(40.0);
        ui.heading(egui::RichText::new("NeXX").size(48.0).strong());
        ui.label(format!(
            "Чисто-Rust мессенджер. Движок: nexxrust (SMP/XFTP wire, crypto, keytree). Версия ядра: {}",
            "0.1.0"
        ));
        ui.add_space(16.0);
        ui.label("Один BIP39 ключ → кошелёк (ETH/BTC/SOL), SMP-идентичность и удалённое управление флотом нод.");
        ui.add_space(24.0);

        if self.mnemonic.is_empty() {
            if ui.button("🔑 Сгенерировать новый ключ (24 слова)").clicked() {
                let entropy = crypto::random_bytes(32);
                match bip39::mnemonic_from_entropy(&entropy) {
                    Ok(words) => {
                        self.mnemonic = words;
                        self.show_seed = true;
                    }
                    Err(e) => self.error = e,
                }
            }
            ui.add_space(8.0);
            ui.label("Или введите существующую мнемонику:");
            // Аудит M4: поле сида — password-режим (маскированный ввод, без эха в буфер обмена по умолчанию).
            ui.add(egui::TextEdit::multiline(&mut self.mnemonic_input).password(true));
        } else {
            ui.label("Ваш seed (запишите, показывается один раз):");
            egui::Frame::dark_canvas(ui.style()).show(ui, |ui| {
                for (i, w) in self.mnemonic.iter().enumerate() {
                    ui.label(format!("{}. {}", i + 1, if self.show_seed { w } else { "••••" }));
                }
            });
            ui.horizontal(|ui| {
                if ui.button("Показать/скрыть").clicked() {
                    self.show_seed = !self.show_seed;
                }
                if ui.button("✅ Подтвердить и войти").clicked() {
                    let m = self.mnemonic.join(" ");
                    if bip39::validate_mnemonic(&self.mnemonic) {
                        let seed = bip39::seed_from_mnemonic_standard(&m, "");
                        self.seed_hex = crypto::hex_encode(&seed);
                        self.seed = seed.clone();
                        self.load_contacts();
                        self.fleet = keytree::plan_fleet(&seed, 5);
                        self.node_status = vec![String::new(); self.fleet.len()];
                        self.node_host = vec!["127.0.0.1".to_string(); self.fleet.len()];
                        self.phase = Phase::Main;
                    } else {
                        self.error = "Мнемоника невалидна".into();
                    }
                }
            });
        }

        if !self.error.is_empty() {
            ui.colored_label(egui::Color32::RED, &self.error);
        }
    }

    fn main(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Chats, "💬 Чаты");
            ui.selectable_value(&mut self.tab, Tab::Contacts, "👤 Контакты");
            ui.selectable_value(&mut self.tab, Tab::Groups, "👥 Группы");
            ui.selectable_value(&mut self.tab, Tab::Proxy, "🔒 Прокси");
            ui.selectable_value(&mut self.tab, Tab::Files, "📎 Файлы");
            ui.selectable_value(&mut self.tab, Tab::Wallet, "💰 Кошелёк");
            ui.selectable_value(&mut self.tab, Tab::Fleet, "🖥️ Флот нод");
        });
        ui.separator();
        match self.tab {
            Tab::Chats => self.chats(ui, ctx),
            Tab::Contacts => self.contacts_ui(ui),
            Tab::Groups => self.groups_ui(ui),
            Tab::Proxy => self.proxy_ui(ui),
            Tab::Files => self.files_ui(ui),
            Tab::Wallet => self.wallet(ui),
            Tab::Fleet => self.fleet(ui),
        }
    }

    /// Вкладка «Группы» (Этап 4.1): список из шифрованного group_store + создание группы.
    /// Сообщения fan-out'ятся per-member E2E (см. rustcore bin/group_smoke.rs — интероп OK).
    /// Вкладка «👥 Группы» (Этап 4.1): двухпанельный вид — слева список групп и создание,
    /// справа чат выбранной группы (пузыри из message_store + fan-out ввод снизу),
    /// участники и добавление из контактов — в правой колонке сверху.
    fn groups_ui(&mut self, ui: &mut egui::Ui) {
        egui::SidePanel::left("groups_list")
            .resizable(true)
            .default_width(240.0)
            .show_inside(ui, |ui| {
                ui.heading("👥 Группы");
                if ui.button("🔄 Загрузить группы").clicked() {
                    let path = std::path::PathBuf::from(format!("{}/groups.bin", data_dir()));
                    match nexxrust::protocols::group_store::GroupStore::open(&path, &self.seed) {
                        Ok(st) => {
                            self.groups = st.groups().to_vec();
                            self.groups_status = format!("✅ загружено групп: {}", self.groups.len());
                        }
                        Err(e) => self.groups_status = format!("⚠ {e}"),
                    }
                }
                ui.horizontal(|ui| {
                    ui.label("Новая:");
                    ui.text_edit_singleline(&mut self.group_name);
                    if ui.button("➕").clicked() {
                        self.groups_status = self.create_group();
                    }
                });
                ui.separator();
                if self.groups.is_empty() {
                    ui.label("Групп пока нет.");
                }
                for (i, g) in self.groups.iter().enumerate() {
                    let selected = i == self.group_selected.min(self.groups.len().saturating_sub(1));
                    if ui.selectable_label(selected, format!("👥 {} ({})", g.name, g.members.len())).clicked() {
                        self.group_selected = i;
                    }
                }
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            if self.groups.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label("Создайте группу слева — и добавьте участников из контактов.");
                });
                return;
            }
            let sel = self.group_selected.min(self.groups.len() - 1);
            let gname = self.groups[sel].name.clone();
            let gid = self.groups[sel].id.clone();
            ui.horizontal(|ui| {
                ui.strong(format!("👥 {gname}"));
                ui.label(format!("{} участников", self.groups[sel].members.len()));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🔄 Принять").clicked() {
                        self.groups_status = self.recv_group_msgs();
                    }
                });
            });
            // участники + добавление из контактов
            ui.horizontal(|ui| {
                for m in &self.groups[sel].members {
                    ui.label(format!("👤 {}…", &m.snd_id[..8.min(m.snd_id.len())]));
                }
                if !self.contacts.is_empty() {
                    let mp = self.member_pick.min(self.contacts.len() - 1);
                    egui::ComboBox::from_id_salt("member_pick")
                        .selected_text(self.contacts[mp].name.clone())
                        .show_ui(ui, |ui| {
                            for (i, c) in self.contacts.iter().enumerate() {
                                ui.selectable_value(&mut self.member_pick, i, c.name.clone());
                            }
                        });
                    if ui.button("➕ в группу").clicked() {
                        self.groups_status = self.add_contact_to_group(sel, mp);
                    }
                }
            });
            ui.separator();
            // история группы — пузыри
            let path = std::path::PathBuf::from(format!("{}/messages.bin", data_dir()));
            let hist: Vec<nexxrust::protocols::message_store::ChatMessage> = nexxrust::protocols::message_store::MessageStore::open(&path, &self.seed)
                .map(|st| st.history(&gid).into_iter().cloned().collect())
                .unwrap_or_default();
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for m in hist.iter().rev().take(50) {
                        let (align, color) = if m.outgoing {
                            (egui::Align::Max, egui::Color32::from_rgb(0x2b, 0x5c, 0xb0))
                        } else {
                            (egui::Align::Min, egui::Color32::from_rgb(0x30, 0x30, 0x34))
                        };
                        ui.with_layout(egui::Layout::top_down(align).with_main_justify(true), |ui| {
                            egui::Frame::none()
                                .fill(color)
                                .rounding(8.0)
                                .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                                .show(ui, |ui| {
                                    ui.set_max_width(ui.available_width() * 0.7);
                                    ui.label(&m.body);
                                });
                        });
                        ui.add_space(4.0);
                    }
                });
            ui.separator();
            // ввод снизу — fan-out на всех member'ов
            let send = ui.horizontal(|ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.group_msg_input)
                        .desired_width(ui.available_width() - 60.0)
                        .hint_text("Сообщение в группу…"),
                );
                let btn = ui.button("📨").clicked()
                    || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                btn && !self.group_msg_input.is_empty()
            }).inner;
            if send {
                self.group_msg_input.clear();
                self.groups_status = self.send_group_msg(sel);
            }
            if !self.groups_status.is_empty() {
                ui.colored_label(egui::Color32::LIGHT_GREEN, &self.groups_status);
            }
        });
    }

    /// Создаёт новую группу в шифрованном group_store.
    fn create_group(&mut self) -> String {
        if self.group_name.trim().is_empty() {
            return "⚠ имя пустое".into();
        }
        let path = std::path::PathBuf::from(format!("{}/groups.bin", data_dir()));
        let mut st = match nexxrust::protocols::group_store::GroupStore::open(&path, &self.seed) {
            Ok(s) => s,
            Err(e) => return format!("⚠ {e}"),
        };
        let creator_pub = nexxrust::crypto::hex_encode(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
                nexxrust::keytree::derive_path_ed25519(&self.seed, "m/0'/0'/1'").unwrap().private,
            ))
            .as_bytes(),
        );
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let gid = match nexxrust::protocols::group_store::GroupStore::id_for(&creator_pub, self.group_name.trim(), ts) {
            Ok(g) => g,
            Err(e) => return format!("⚠ {e}"),
        };
        let g = nexxrust::protocols::group_store::GroupRecord {
            id: gid.clone(),
            name: self.group_name.trim().to_string(),
            creator_pub,
            members: vec![],
            created_at: ts,
        };
        match st.upsert(g) {
            Ok(()) => {
                let n = st.groups().len();
                drop(st);
                self.load_groups_from_disk();
                self.group_name.clear();
                format!("✅ группа создана id={gid} (всего {n})")
            }
            Err(e) => format!("⚠ {e}"),
        }
    }

    fn load_groups_from_disk(&mut self) {
        let path = std::path::PathBuf::from(format!("{}/groups.bin", data_dir()));
        if let Ok(st) = nexxrust::protocols::group_store::GroupStore::open(&path, &self.seed) {
            self.groups = st.groups().to_vec();
        }
    }

    /// Добавляет контакт в выбранную группу как member (нужны peer_snd_id и dh pub).
    fn add_contact_to_group(&mut self, gi: usize, ci: usize) -> String {
        use nexxrust::protocols::group_store::{GroupMember, GroupStore};
        let c = match self.contacts.get(ci) {
            Some(c) => c.clone(),
            None => return "нет такого контакта".into(),
        };
        if c.peer_snd_id.is_empty() {
            return "⚠ у контакта ещё нет peer_snd_id (нужен обмен очередями QADD)".into();
        }
        let dh_raw = crypto::hex_decode(&c.peer_pub)
            .and_then(|der| nexxrust::protocols::smp::parse_x25519_x509(&der).map(|k| k.to_vec()));
        let dh_pub = match dh_raw {
            Some(k) => crypto::hex_encode(&k),
            None => return "⚠ peer_pub не x25519".into(),
        };
        let path = std::path::PathBuf::from(format!("{}/groups.bin", data_dir()));
        let mut st = match GroupStore::open(&path, &self.seed) {
            Ok(s) => s,
            Err(e) => return format!("⚠ {e}"),
        };
        let g = match st.groups().get(gi).cloned() {
            Some(g) => g,
            None => return "группа не найдена".into(),
        };
        if g.members.iter().any(|m| m.contact_id == c.id) {
            return "⚠ контакт уже в группе".into();
        }
        let mut g = g;
        g.members.push(GroupMember {
            contact_id: c.id.clone(),
            host: c.host.clone(),
            port: c.port,
            snd_id: c.peer_snd_id.clone(),
            dh_pub,
        });
        match st.upsert(g) {
            Ok(()) => {
                self.groups = st.groups().to_vec();
                format!("✅ {} добавлен в группу", c.name)
            }
            Err(e) => format!("⚠ {e}"),
        }
    }

    /// Запись сообщения 1-1 линка в шифрованную историю (contact_id = link_peer).
    fn store_link_msg(&self, outgoing: bool, body: &str) {
        if self.link_peer.is_empty() || self.seed.is_empty() { return; }
        let path = std::path::PathBuf::from(format!("{}/messages.bin", data_dir()));
        if let Ok(mut ms) = nexxrust::protocols::message_store::MessageStore::open(&path, &self.seed) {
            let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let _ = ms.push(nexxrust::protocols::message_store::ChatMessage {
                contact_id: self.link_peer.clone(),
                outgoing,
                body: body.to_string(),
                ts,
            });
        }
    }

    /// Приём групповых сообщений: poll всех своих очередей, два слоя шифрования,
    /// фильтр по group_id известных групп, запись в message_store, ACK.
    fn recv_group_msgs(&mut self) -> String {
        use nexxrust::protocols::group_store::decode_group_msg;
        use nexxrust::protocols::message_store::{ChatMessage, MessageStore};
        use nexxrust::protocols::queue_store::{derive_queue_keys, QueueStore};
        use nexxrust::protocols::smp;
        use nexxrust::protocols::smp_client::SmpClient;
        use x25519_dalek::PublicKey as X25519Public;
        if self.seed.is_empty() {
            return "⚠ нет сида".into();
        }
        if !self.route_allowed() {
            return "🚫 kill-switch: прокси не активен".into();
        }
        let qpath = std::path::PathBuf::from(format!("{}/queues.bin", data_dir()));
        let store = match QueueStore::open(&qpath, &self.seed) {
            Ok(s) => s,
            Err(e) => return format!("⚠ queue store: {e}"),
        };
        let group_ids: Vec<String> = self.groups.iter().map(|g| g.id.clone()).collect();
        let mut got = 0usize;
        let mut errs = Vec::new();
        for rec in store.records() {
            let keys = match derive_queue_keys(&self.seed, rec.index) {
                Ok(k) => k,
                Err(e) => {
                    errs.push(format!("{}: keys {e}", rec.label));
                    continue;
                }
            };
            let ca = crate::servers::ca_for(&rec.host, rec.port);
            let mut client = match SmpClient::connect_openssl_with_ca(&rec.host, rec.port, ca.as_deref()) {
                Ok(c) => c,
                Err(e) => {
                    errs.push(format!("{}:{} connect {e}", rec.host, rec.port));
                    continue;
                }
            };
            let rcv_id = match crypto::hex_decode(&rec.rcv_id) {
                Some(b) => b,
                None => continue,
            };
            let srv_dh = crypto::hex_decode(&rec.srv_dh_pub)
                .and_then(|der| smp::parse_x25519_x509(&der).map(|k| k.to_vec()));
            let srv_key = match srv_dh {
                Some(sp) => keys.dh.diffie_hellman(&X25519Public::from(<[u8; 32]>::try_from(sp.as_slice()).unwrap_or([0u8; 32]))),
                None => {
                    errs.push(format!("{}: нет srv_dh_pub", rec.label));
                    continue;
                }
            };
            if client.subscribe(&rcv_id, &keys.auth).is_err() {
                continue;
            }
            client.set_poll_timeout(std::time::Duration::from_millis(400));
            for _ in 0..12 {
                // сначала pending (MSG в том же batch, что и ответ на SUB/ACK)
                let pend = client.take_pending();
                let items = match client.recv_transmissions() {
                    Ok(it) => it,
                    Err(_) => vec![],
                };
                let had_pending = !pend.is_empty();
                let mut all: Vec<Vec<u8>> = pend;
                all.extend(items.into_iter().map(|(_a, _c, _e, cmd)| cmd));
                for cmd in all {
                    let Ok(m) = smp::parse_msg(&cmd) else { continue };
                    let Ok(rcv) = smp::decrypt_rcv_msg(srv_key.as_bytes(), &m.msg_id, &m.body) else { continue };
                    // e2e ключ = наш dh × эфемерный ключ отправителя из конверта
                    let Ok((env, plain)) = smp::decrypt_client_msg(&{
                        let eph_pub = env_eph(&rcv.envelope);
                        match eph_pub {
                            Some(p) => keys.dh.diffie_hellman(&X25519Public::from(p)),
                            None => continue,
                        }
                    }.as_bytes(), &rcv.envelope) else { continue };
                    let _ = env;
                    let Ok((_ph, body)) = smp::parse_priv_header(&plain) else { continue };
                    if let Ok(gm) = decode_group_msg(body) {
                        if group_ids.contains(&gm.group_id) {
                            let body_text = crypto::base64_decode(&gm.body_b64)
                                .map(|b| String::from_utf8_lossy(&b).into_owned())
                                .unwrap_or_default();
                            let mpath = std::path::PathBuf::from(format!("{}/messages.bin", data_dir()));
                            if let Ok(mut ms) = MessageStore::open(&mpath, &self.seed) {
                                let _ = ms.push(ChatMessage {
                                    contact_id: gm.group_id.clone(),
                                    outgoing: false,
                                    body: body_text,
                                    ts: gm.ts,
                                });
                            }
                            got += 1;
                        }
                    }
                    let _ = client.ack(&rcv_id, &keys.auth, &m.msg_id);
                }
                if had_pending {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
        }
        if got > 0 {
            format!("✅ принято групповых сообщений: {got}")
        } else if errs.is_empty() {
            "Групповых сообщений нет".into()
        } else {
            format!("⚠ {}", errs.join("; "))
        }
    }
    fn send_group_msg(&mut self, gi: usize) -> String {
        use nexxrust::protocols::group_store::{encode_group_msg, GroupMsg};
        use nexxrust::protocols::smp;
        use nexxrust::protocols::smp_client::SmpClient;
        use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
        let text = self.group_msg_input.trim().to_string();
        if text.is_empty() {
            return "⚠ пустое сообщение".into();
        }
        let g = match self.groups.get(gi).cloned() {
            Some(g) => g,
            None => return "группа не найдена".into(),
        };
        if g.members.is_empty() {
            return "⚠ в группе нет участников".into();
        }
        // kill-switch: без прокси при включённом kill-switch — refuse
        if !self.route_allowed() {
            return "🚫 kill-switch: прокси не активен".into();
        }
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let msg = GroupMsg {
            v: "nexx/group/v1".into(),
            group_id: g.id.clone(),
            from_contact: "me".into(),
            ts,
            body_b64: crypto::base64url_encode(text.as_bytes()),
        };
        let plain = match encode_group_msg(&msg) {
            Ok(p) => p,
            Err(e) => return format!("⚠ {e}"),
        };
        let mut ok = 0usize;
        let mut last_err = String::new();
        for m in &g.members {
            let dh_bytes = match crypto::hex_decode(&m.dh_pub) {
                Some(b) if b.len() == 32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                }
                _ => {
                    last_err = format!("member {} dh_pub не 32 байта", m.contact_id);
                    continue;
                }
            };
            let snd_id = match crypto::hex_decode(&m.snd_id) {
                Some(b) => b,
                None => {
                    last_err = format!("member {} snd_id не hex", m.contact_id);
                    continue;
                }
            };
            let ca = crate::servers::ca_for(&m.host, m.port);
            let mut client = match SmpClient::connect_openssl_with_ca(&m.host, m.port, ca.as_deref()) {
                Ok(c) => c,
                Err(e) => {
                    last_err = format!("{}:{} connect: {e}", m.host, m.port);
                    continue;
                }
            };
            let mut eph_b = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut eph_b);
            let eph = StaticSecret::from(eph_b);
            let e2e = eph.diffie_hellman(&X25519Public::from(dh_bytes));
            let eph_x = smp::x25519_x509(X25519Public::from(&eph).as_bytes());
            let mut body = vec![b'_'];
            body.extend_from_slice(&plain);
            match client.send_message(&snd_id, e2e.as_bytes(), Some(&eph_x), &body, b"") {
                Ok(()) => ok += 1,
                Err(e) => last_err = format!("{}:{} SEND: {e}", m.host, m.port),
            }
        }
        if ok > 0 {
            self.group_msg_input.clear();
            format!("✅ отправлено участникам: {ok}/{} мест", g.members.len())
        } else {
            format!("❌ никому не ушло: {last_err}")
        }
    }

    /// Вкладка «Прокси» (Этап 4.3): импорт ss:// / vless:// / vmess:// / trojan:// /
    /// wg-conf / xray-json или base64-подписки, health-check, kill-switch.
    /// Kill-switch: пока прокси не активен и kill_switch включён — route_decision = block,
    /// и чат refused (см. chats()).
    fn proxy_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔒 Прокси и kill-switch");
        ui.horizontal(|ui| {
            ui.label("Kill-switch:");
            if ui.button(if self.kill_switch { "🟢 ВКЛ (блок без прокси)" } else { "🔴 ВЫКЛ" }).clicked() {
                self.kill_switch = !self.kill_switch;
            }
        });
        let decision = nexxrust::control::route_decision(
            self.proxy_active || self.runtime.port().is_some(), false, false, false, !self.kill_switch,
        );
        ui.label(format!("Текущее решение маршрута: {decision}"));
        if let Some(p) = self.runtime.port() {
            ui.label(format!("🧦 локальный SOCKS5: 127.0.0.1:{p} (приложения ходят через него)"));
        }
        ui.horizontal(|ui| {
            let running = self.runtime.port().is_some();
            if ui.button(if running { "■ Остановить SOCKS5" } else { "▶ Запустить локальный SOCKS5" }).clicked() {
                let lock = format!("{}/nexx_ports.lock", data_dir());
                if running {
                    self.runtime.stop(&lock);
                    self.proxy_status = "⏸ SOCKS5 остановлен, kill-switch снова блокирует прямой трафик".into();
                } else {
                    let p = self.runtime.start(&lock, 21000, 21999);
                    if p > 0 {
                        if let Some(xp) = self.xray_port {
                            self.runtime.set_upstream(Some(("127.0.0.1".into(), xp)));
                        }
                    }
                    self.proxy_status = if p > 0 {
                        self.proxy_active = true;
                        format!("✅ SOCKS5 поднят на 127.0.0.1:{p} — kill-switch пройден")
                    } else {
                        "⚠ не удалось выделить порт 21000-21999".into()
                    };
                }
            }
        });
        ui.separator();
        ui.label("Конфиг / подписка (ss://, vless://, vmess://, trojan://, [Interface], xray JSON или base64):");
        ui.add(egui::TextEdit::multiline(&mut self.proxy_input).desired_rows(3));
        if ui.button("🔍 Распарсить").clicked() {
            match self.parse_proxy_input() {
                Ok(n) => self.proxy_status = format!("✅ распарсено узлов: {n}"),
                Err(e) => self.proxy_status = format!("⚠ {e}"),
            }
        }
        if !self.proxy_list.is_empty() {
            egui::ComboBox::from_id_salt("proxy_pick")
                .selected_text(self.proxy_list[self.proxy_selected.min(self.proxy_list.len() - 1)].0.clone())
                .show_ui(ui, |ui| {
                    for (i, (r, _)) in self.proxy_list.iter().enumerate() {
                        ui.selectable_value(&mut self.proxy_selected, i, r.clone());
                    }
                });
            ui.horizontal(|ui| {
                if ui.button("🩺 Health-check").clicked() {
                    self.proxy_status = self.health_check_selected();
                }
                if ui.button("▶ Xray-ядро (libv2ray)").clicked() {
                    self.proxy_status = self.start_xray_core();
                }
                if self.xray_port.is_some() && ui.button("■ Стоп Xray").clicked() {
                    self.proxy_status = self.stop_xray_core();
                }
                if ui.button(if self.proxy_active { "■ Выключить прокси" } else { "▶ Включить прокси" }).clicked() {
                    self.proxy_active = !self.proxy_active;
                    self.proxy_status = if self.proxy_active {
                        "✅ прокси активен — трафик идёт через него (kill-switch пройден)".into()
                    } else {
                        "⏸ прокси выключен".into()
                    };
                }
            });
        }
        if !self.proxy_status.is_empty() {
            ui.colored_label(egui::Color32::LIGHT_GREEN, &self.proxy_status);
        }
    }

    /// Парсит proxy_input: если это не scheme-URI, пробует base64-подписку (каждая строка — узел).
    fn parse_proxy_input(&mut self) -> Result<usize, String> {
        let input = self.proxy_input.trim().to_string();
        if input.is_empty() {
            return Err("пустой ввод".into());
        }
        let mut items: Vec<(String, String)> = Vec::new();
        if input.contains("://") || input.starts_with('[') || input.starts_with('{') {
            let j = nexxrust::proxy_parse::parse_proxy_config(&input, "manual");
            let v: serde_json::Value = serde_json::from_str(&j).map_err(|e| e.to_string())?;
            if v.get("ok").and_then(|b| b.as_bool()) != Some(true) {
                return Err(v.get("error").and_then(|e| e.as_str()).unwrap_or("parse error").to_string());
            }
            items.push((v.get("remarks").or_else(|| v.get("tag")).and_then(|r| r.as_str()).unwrap_or("manual").to_string(), j));
        } else {
            // base64-подписка
            let raw = crypto::base64url_decode(&input)
                .or_else(|_| crypto::base64_decode(&input))
                .map_err(|_| "не URI и не base64".to_string())?;
            let text = String::from_utf8(raw).map_err(|_| "подписка не текст".to_string())?;
            for (i, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let j = nexxrust::proxy_parse::parse_proxy_config(line, &format!("node-{}", i + 1));
                let v: serde_json::Value = serde_json::from_str(&j).map_err(|e| e.to_string())?;
                if v.get("ok").and_then(|b| b.as_bool()) == Some(true) {
                    let remarks = v.get("remarks").or_else(|| v.get("tag")).and_then(|r| r.as_str()).unwrap_or("").to_string();
                    items.push((if remarks.is_empty() { format!("node-{}", i + 1) } else { remarks }, j));
                }
            }
        }
        if items.is_empty() {
            return Err("ни одного валидного узла".into());
        }
        self.proxy_list = items;
        self.proxy_selected = 0;
        Ok(self.proxy_list.len())
    }

    /// Запуск Xray-ядра (libv2ray) с выбранным прокси как outbound: SOCKS5-in на 127.0.0.1.
    fn start_xray_core(&mut self) -> String {
        if self.proxy_list.is_empty() {
            return "⚠ сначала распарсьте конфиг выше".into();
        }
        let (_, j) = &self.proxy_list[self.proxy_selected.min(self.proxy_list.len() - 1)];
        let v: serde_json::Value = match serde_json::from_str(j) {
            Ok(v) => v,
            Err(_) => return "битый json узла".into(),
        };
        let proto = v.get("protocol").and_then(|p| p.as_str()).unwrap_or("").to_string();
        let cfg_json = v.get("config_json").and_then(|c| c.as_str()).unwrap_or("{}");
        let outbound = match serde_json::from_str::<serde_json::Value>(cfg_json) {
            Ok(inner) if inner.get("protocol").is_some() => {
                let mut o = inner;
                o["tag"] = serde_json::json!("proxy");
                o
            }
            _ => serde_json::json!({
                "tag": "proxy",
                "protocol": if proto.is_empty() { "shadowsocks" } else { &proto },
                "settings": serde_json::from_str::<serde_json::Value>(cfg_json).unwrap_or(serde_json::json!({})),
            }),
        };
        let user_cfg = serde_json::json!({"outbounds": [outbound]}).to_string();
        let port = self.runtime.port().unwrap_or(21080);
        let cfg = match crate::v2ray_bridge::socks_config(port, &user_cfg) {
            Ok(c) => c,
            Err(e) => return format!("⚠ config: {e}"),
        };
        let assets = format!("{}/v2ray_assets", data_dir());
        if let Err(e) = crate::v2ray_bridge::extract_assets(&assets) {
            return format!("⚠ assets: {e}");
        }
        match crate::v2ray_bridge::start(&assets, "nexx-android", &cfg) {
            Ok(()) => {
                self.proxy_active = true;
                self.xray_port = Some(port);
                // если локальный SOCKS5 поднят — направляем его через Xray-ядро
                self.runtime.set_upstream(Some(("127.0.0.1".into(), port)));
                format!("✅ Xray-ядро запущено: SOCKS5 127.0.0.1:{port} → {proto}; локальный SOCKS5 направлен через него")
            }
            Err(e) => format!("❌ Xray start: {e}"),
        }
    }

    /// Остановка Xray-ядра и сброс upstream у локального SOCKS5.
    fn stop_xray_core(&mut self) -> String {
        crate::v2ray_bridge::stop();
        self.xray_port = None;
        self.runtime.set_upstream(None);
        "⏸ Xray-ядро остановлено, локальный SOCKS5 снова прямой".into()
    }

    fn health_check_selected(&self) -> String {
        if self.proxy_list.is_empty() {
            return "нет узлов".into();
        }
        let (_, j) = &self.proxy_list[self.proxy_selected.min(self.proxy_list.len() - 1)];
        let v: serde_json::Value = match serde_json::from_str(j) {
            Ok(v) => v,
            Err(_) => return "битый json узла".into(),
        };
        let host = v.get("host").and_then(|h| h.as_str()).unwrap_or("");
        let port = v.get("port").and_then(|p| p.as_u64()).unwrap_or(0) as u16;
        if host.is_empty() || port == 0 {
            return "в узле нет host/port".into();
        }
        let r = nexxrust::control::health_check_tcp(host, port, 3000);
        if r.get("ok").and_then(|b| b.as_bool()) == Some(true) {
            format!("✅ {host}:{port} — {} мс", r.get("rtt_ms").and_then(|x| x.as_u64()).unwrap_or(0))
        } else {
            format!("❌ {host}:{port} — {}", r.get("error").and_then(|e| e.as_str()).unwrap_or("timeout"))
        }
    }

    /// Kill-switch проверка перед любым сетевым действием приложения.
    fn route_allowed(&self) -> bool {
        nexxrust::control::route_decision(self.proxy_active, false, false, false, !self.kill_switch) != "block"
    }

    /// Вкладка «Контакты» (Этап 2.2): список из шифрованного contact_store +
    /// добавление по инвайт-ссылке (connReq URI). Обмен очередями — invite_flow.
    fn contacts_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("👤 Контакты");
        if self.contacts.is_empty() {
            ui.label("Пока пусто. Добавьте контакт по инвайт-ссылке ниже.");
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            for c in &self.contacts {
                ui.horizontal(|ui| {
                    ui.label(format!("👤 {}  ({}:{})", c.name, c.host, c.port));
                });
            }
        });
        ui.separator();
        ui.label("Добавить контакт по ссылке:");
        ui.text_edit_singleline(&mut self.contact_name);
        ui.add(egui::TextEdit::multiline(&mut self.invite_input).desired_rows(2));
        if ui.button("➕ Добавить").clicked() {
            match self.add_contact_from_invite() {
                Ok(name) => {
                    self.contacts_status = format!("✅ контакт {name} добавлен");
                    self.invite_input.clear();
                    self.contact_name.clear();
                }
                Err(e) => self.contacts_status = format!("⚠ {e}"),
            }
        }
        if !self.contacts_status.is_empty() {
            ui.colored_label(egui::Color32::LIGHT_GREEN, &self.contacts_status);
        }
    }

    fn load_contacts(&mut self) {
        if self.seed.is_empty() {
            return;
        }
        let path = std::path::PathBuf::from(format!("{}/contacts.bin", data_dir()));
        match nexxrust::protocols::contact_store::ContactStore::open(&path, &self.seed) {
            Ok(st) => self.contacts = st.contacts().to_vec(),
            Err(e) => self.contacts_status = format!("⚠ contact store: {e}"),
        }
    }

    /// Парсит инвайт-ссылку, валидирует релей по конфигу (M6), сохраняет контакт.
    fn add_contact_from_invite(&mut self) -> Result<String, String> {
        use nexxrust::protocols::connreq;
        use nexxrust::protocols::contact_store::{ContactRecord, ContactStore};
        let uri = self.invite_input.trim().to_string();
        if uri.is_empty() {
            return Err("пустая ссылка".into());
        }
        let cr = connreq::decode_invite_uri(&uri).map_err(|e| format!("невалидная ссылка: {e}"))?;
        let q = cr.queues.first().ok_or("в ссылке нет очередей")?;
        // M6: релей из ссылки должен быть в конфиге, иначе отказ (не чужой CA)
        if crate::servers::find(&q.host, q.port).is_none() {
            return Err(format!("неизвестный релей {}:{} — добавьте в servers.rs", q.host, q.port));
        }
        let name = if self.contact_name.trim().is_empty() {
            format!("contact-{}", &crypto::hex_encode(&q.sender_id)[..8])
        } else {
            self.contact_name.trim().to_string()
        };
        let peer_pub_hex = crypto::hex_encode(&q.dh_x509);
        let id = ContactStore::id_for_peer_pub(&peer_pub_hex)?;
        let rec = ContactRecord {
            id: id.clone(),
            name: name.clone(),
            my_queue_label: format!("contact@{id}@{}:{}", q.host, q.port),
            peer_rcv_id: crypto::hex_encode(&q.sender_id),
            peer_snd_id: String::new(), // заполнится после обмена очередями (QADD)
            host: q.host.clone(),
            port: q.port,
            peer_pub: peer_pub_hex,
            conn_req: uri,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        let path = std::path::PathBuf::from(format!("{}/contacts.bin", data_dir()));
        let mut st = ContactStore::open(&path, &self.seed).map_err(|e| e)?;
        st.upsert(rec).map_err(|e| e)?;
        self.contacts = st.contacts().to_vec();
        Ok(name)
    }

    /// Двухпанельный чат как в Telegram: слева список, справа переписка + ввод снизу.
    fn chats(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        // drains событий воркера
        if let Some(rx) = &self.chat_rx {
            while let Ok(e) = rx.try_recv() {
                match e {
                    ChatEvent::Status(s) => self.chat_status = s,
                    ChatEvent::Ready(rcv) => {
                        self.chat_ready = true;
                        self.chat_rcv = rcv;
                        self.chat_status = "online".into();
                    }
                    ChatEvent::Incoming(body) => self.chat_msgs.push(ChatMsg { outgoing: false, body }),
                    ChatEvent::SentOk => {}
                    ChatEvent::Err(e) => self.chat_status = format!("⚠ {e}"),
                }
            }
        }
        // drains событий 1-1 линка
        if let Some(rx) = &self.link_rx {
            while let Ok(e) = rx.try_recv() {
                match e {
                    LinkEvent::Status(s) => self.link_status = s,
                    LinkEvent::MyInvite(u) => self.my_invite = u,
                    LinkEvent::PeerReady(p) => {
                        self.link_ready = true;
                        self.link_status = format!("🟢 peer установлен: {p}…");
                        self.link_peer = p.clone();
                        // подгружаем сохранённую историю этого peer из шифрованного стора
                        if self.link_msgs.is_empty() && !self.seed.is_empty() {
                            let mp = std::path::PathBuf::from(format!("{}/messages.bin", data_dir()));
                            if let Ok(ms) = nexxrust::protocols::message_store::MessageStore::open(&mp, &self.seed) {
                                self.link_msgs = ms.history(&p).into_iter().rev().map(|m| ChatMsg {
                                    outgoing: m.outgoing,
                                    body: m.body.clone(),
                                }).collect();
                            }
                        }
                    }
                    LinkEvent::Incoming(b) => {
                        self.link_msgs.push(ChatMsg { outgoing: false, body: b.clone() });
                        self.store_link_msg(false, &b);
                    }
                    LinkEvent::SentOk => {}
                    LinkEvent::Err(e) => self.link_status = format!("⚠ {e}"),
                }
            }
        }
        let _ = ctx;
        egui::SidePanel::left("chat_list")
            .resizable(true)
            .default_width(260.0)
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("💬 NeXX");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let dot = if self.chat_ready { "🟢" } else { "🔴" };
                        ui.label(format!("{dot} {}", self.chat_status));
                    });
                });
                ui.separator();
                if !self.chat_ready {
                    ui.label("Релей:");
                    // Аудит M6: релеи берём из servers::SERVERS, а не из хардкода.
                    let mut selected = crate::servers::SERVERS
                        .iter()
                        .position(|s| s.host == self.chat_host && s.port == self.chat_port)
                        .unwrap_or(0);
                    egui::ComboBox::from_id_salt("server_pick")
                        .selected_text(crate::servers::SERVERS[selected].name)
                        .show_ui(ui, |ui| {
                            for (i, s) in crate::servers::SERVERS.iter().enumerate() {
                                ui.selectable_value(&mut selected, i, s.name);
                            }
                        });
                    let srv = &crate::servers::SERVERS[selected];
                    self.chat_host = srv.host.to_string();
                    self.chat_port = srv.port;
                    ui.horizontal(|ui| {
                        ui.label(format!("{}:{}", self.chat_host, self.chat_port));
                    });
                    if ui.button("Подключиться").clicked() {
                        // Kill-switch (Этап 4.3): без активного прокси при включённом
                        // kill-switch refuse — никакого прямого трафика.
                        if !self.route_allowed() {
                            self.chat_status = "🚫 kill-switch: прокси не активен, прямой трафик заблокирован".into();
                            return;
                        }
                        // M6: CA только из конфига; неизвестный хост — отказ, не чужой CA.
                        let Some(ca_pem) = crate::servers::ca_for(&self.chat_host, self.chat_port) else {
                            self.chat_status = format!("неизвестный релей {}:{}", self.chat_host, self.chat_port);
                            return;
                        };
                        let seed = crypto::hex_decode(&self.seed_hex).unwrap_or_default();
                        let (ev_tx, ev_rx) = channel::<ChatEvent>();
                        let (cmd_tx, cmd_rx) = channel::<WorkerCmd>();
                        self.chat_rx = Some(ev_rx);
                        self.chat_tx = Some(cmd_tx);
                        self.chat_status = "connecting…".into();
                        let host = self.chat_host.clone();
                        let port = self.chat_port;
                        std::thread::spawn(move || chat_worker(host, port, ca_pem, seed, ev_tx, cmd_rx));
                    }
                } else {
                    ui.label(format!("Мой адрес: {}…", &self.chat_rcv[..self.chat_rcv.len().min(16)]));
                    ui.add_space(8.0);
                    let row = egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("💬");
                            ui.vertical(|ui| {
                                ui.strong("Self (тестовая очередь)");
                                ui.small(format!("{} сообщений", self.chat_msgs.len()));
                            });
                        });
                    });
                    if row.response.interact(egui::Sense::click()).clicked() {}
                }
                ui.separator();
                ui.strong("🔗 1-1 линк (контакты)");
                if self.link_tx.is_none() {
                    if ui.button("🔗 Поднять 1-1 линк").clicked() {
                        if !self.route_allowed() {
                            self.link_status = "🚫 kill-switch: без прокси линк не поднимается".into();
                        } else if let Some(ca_pem) = crate::servers::ca_for(&self.chat_host, self.chat_port) {
                            let seed = crypto::hex_decode(&self.seed_hex).unwrap_or_default();
                            let (ev_tx, ev_rx) = channel::<LinkEvent>();
                            let (cmd_tx, cmd_rx) = channel::<LinkCmd>();
                            self.link_rx = Some(ev_rx);
                            self.link_tx = Some(cmd_tx);
                            self.link_status = "link: NEW+SUB…".into();
                            let host = self.chat_host.clone();
                            let port = self.chat_port;
                            std::thread::spawn(move || link_worker(host, port, ca_pem, seed, ev_tx, cmd_rx));
                        } else {
                            self.link_status = "неизвестный релей для линка".into();
                        }
                    }
                } else {
                    ui.label(format!("статус: {}", self.link_status));
                    if !self.my_invite.is_empty() {
                        ui.label("Мой инвайт (дайте собеседнику):");
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::multiline(&mut self.my_invite.clone()).desired_rows(2).desired_width(220.0).interactive(false));
                            if ui.button("📋").clicked() {
                                ui.output_mut(|o| o.copied_text = self.my_invite.clone());
                            }
                        });
                    }
                    ui.label("Принять инвайт собеседника:");
                    ui.text_edit_singleline(&mut self.link_invite_input);
                    if ui.button("🤝 Принять").clicked() && !self.link_invite_input.is_empty() {
                        if let Some(tx) = &self.link_tx {
                            let _ = tx.send(LinkCmd::AcceptInvite(self.link_invite_input.trim().to_string()));
                            self.link_invite_input.clear();
                        }
                    }
                    if self.link_ready {
                        ui.label(format!("🟢 peer: {}…", &self.link_peer[..self.link_peer.len().min(12)]));
                    }
                }
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            // Если поднят 1-1 линк и peer установлен — показываем чат с peer,
            // иначе — self-chat.
            if self.link_ready {
                ui.horizontal(|ui| {
                    ui.strong("🔗 1-1");
                    ui.label(format!("peer {}…", &self.link_peer[..self.link_peer.len().min(12)]));
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for m in &self.link_msgs {
                            let (align, color) = if m.outgoing {
                                (egui::Align::Max, egui::Color32::from_rgb(0x2b, 0x5c, 0xb0))
                            } else {
                                (egui::Align::Min, egui::Color32::from_rgb(0x30, 0x30, 0x34))
                            };
                            ui.with_layout(egui::Layout::top_down(align).with_main_justify(true), |ui| {
                                egui::Frame::none()
                                    .fill(color)
                                    .rounding(8.0)
                                    .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                                    .show(ui, |ui| {
                                        ui.set_max_width(ui.available_width() * 0.7);
                                        ui.label(&m.body);
                                    });
                            });
                            ui.add_space(4.0);
                        }
                    });
                ui.separator();
                let send = ui.horizontal(|ui| {
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.link_input)
                            .desired_width(ui.available_width() - 60.0)
                            .hint_text("Сообщение peer'у…"),
                    );
                    let btn = ui.button("➤").clicked()
                        || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                    btn && !self.link_input.is_empty()
                }).inner;
                if send {
                    let text = std::mem::take(&mut self.link_input);
                    if let Some(tx) = &self.link_tx {
                        let _ = tx.send(LinkCmd::Send(text.clone()));
                        self.store_link_msg(true, &text);
                        self.link_msgs.push(ChatMsg { outgoing: true, body: text });
                    }
                }
                return;
            }
            if !self.chat_ready {
                ui.centered_and_justified(|ui| {
                    ui.label("Подключись к релею слева — и можно писать самому себе через публичную сеть SimpleX.");
                });
                return;
            }
            // шапка чата — минимум
            ui.horizontal(|ui| {
                ui.strong("Self");
                ui.label(format!("rcv {}…", &self.chat_rcv[..self.chat_rcv.len().min(12)]));
            });
            ui.separator();
            // сообщения
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for m in &self.chat_msgs {
                        let (align, color) = if m.outgoing {
                            (egui::Align::Max, egui::Color32::from_rgb(0x2b, 0x5c, 0xb0))
                        } else {
                            (egui::Align::Min, egui::Color32::from_rgb(0x30, 0x30, 0x34))
                        };
                        ui.with_layout(egui::Layout::top_down(align).with_main_justify(true), |ui| {
                            egui::Frame::none()
                                .fill(color)
                                .rounding(8.0)
                                .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                                .show(ui, |ui| {
                                    ui.set_max_width(ui.available_width() * 0.7);
                                    ui.label(&m.body);
                                });
                        });
                        ui.add_space(4.0);
                    }
                });
            ui.separator();
            // ввод снизу
            let send = ui.horizontal(|ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.chat_input)
                        .desired_width(ui.available_width() - 60.0)
                        .hint_text("Сообщение…"),
                );
                let btn = ui.button("➤").clicked()
                    || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                btn && !self.chat_input.is_empty()
            }).inner;
            if send {
                let text = std::mem::take(&mut self.chat_input);
                if let Some(tx) = &self.chat_tx {
                    let _ = tx.send(WorkerCmd::Send(text.clone()));
                    self.chat_msgs.push(ChatMsg { outgoing: true, body: text });
                }
            }
        });
    }

    /// Вкладка «📎 Файлы» (Этап 3.2): XFTP chunked upload → link nexx://file#/…,
    /// приём по link → download в data_dir/downloads.
    fn files_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("📎 Файлы (XFTP chunked, 64KB packets)");
        if let Some(rx) = &self.file_rx {
            while let Ok(e) = rx.try_recv() {
                match e {
                    FileEvent::Status(s) => self.file_status = s,
                    FileEvent::Link(l) => { self.file_link = l; self.file_status = "✅ загружено, link ниже".into(); }
                    FileEvent::Saved(p) => {
                        self.file_status = format!("✅ сохранено: {p}");
                        let ext = std::path::Path::new(&p).extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                        if matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "webp" | "gif" | "bmp") {
                            if let Ok(bytes) = std::fs::read(&p) {
                                if let Ok(img) = image::load_from_memory(&bytes) {
                                    let rgba = img.to_rgba8();
                                    let (w, h) = (rgba.width() as usize, rgba.height() as usize);
                                    let tex = ui.ctx().load_texture(
                                        format!("file_preview_{p}"),
                                        egui::ColorImage::from_rgba_unmultiplied([w, h], rgba.as_raw()),
                                        egui::TextureOptions::LINEAR,
                                    );
                                    self.file_preview = Some(tex);
                                    self.file_preview_name = p.clone();
                                } else {
                                    self.file_preview = None;
                                }
                            }
                        } else {
                            self.file_preview = None;
                        }
                    }
                    FileEvent::Err(e) => self.file_status = format!("⚠ {e}"),
                }
            }
        }
        ui.label("XFTP-релей: xftp1.simplex.im:443 (ALPN xftp/1, пиннинг по keyHash CA в clientHello)");
        // drag&drop файла в окно — автозаполнение пути и сразу загрузка
        let dropped = ui.input(|i| i.raw.dropped_files.clone());
        if let Some(f) = dropped.first() {
            if let Some(path) = &f.path {
                self.file_path = path.display().to_string();
                if self.file_tx.is_none() {
                    let (ev_tx, ev_rx) = channel::<FileEvent>();
                    let (cmd_tx, cmd_rx) = channel::<FileCmd>();
                    self.file_rx = Some(ev_rx);
                    self.file_tx = Some(cmd_tx);
                    std::thread::spawn(move || file_worker(ev_tx, cmd_rx));
                }
                if let Some(tx) = &self.file_tx {
                    let _ = tx.send(FileCmd::Upload(self.file_path.clone()));
                    self.file_status = format!("загрузка перетащенного файла: {}", self.file_path);
                }
            }
        }
        if ui.input(|i| !i.raw.dropped_files.is_empty() && i.raw.dropped_files[0].path.is_none()) {
            ui.painter().text(
                ui.ctx().screen_rect().center(),
                egui::Align2::CENTER_CENTER,
                "⬆ отпустите файл для загрузки",
                egui::FontId::proportional(28.0),
                egui::Color32::LIGHT_GREEN,
            );
        }
        ui.separator();
        ui.strong("Отправка файла:");
        ui.horizontal(|ui| {
            ui.label("путь:");
            ui.text_edit_singleline(&mut self.file_path);
            if ui.button("⬆ Загрузить").clicked() && !self.file_path.is_empty() {
                if self.file_tx.is_none() {
                    let (ev_tx, ev_rx) = channel::<FileEvent>();
                    let (cmd_tx, cmd_rx) = channel::<FileCmd>();
                    self.file_rx = Some(ev_rx);
                    self.file_tx = Some(cmd_tx);
                    std::thread::spawn(move || file_worker(ev_tx, cmd_rx));
                }
                if let Some(tx) = &self.file_tx {
                    let _ = tx.send(FileCmd::Upload(self.file_path.clone()));
                    self.file_status = "загрузка…".into();
                }
            }
        });
        if !self.file_link.is_empty() {
            ui.label("Ссылка на файл (дайте собеседнику / вставьте в чат):");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::multiline(&mut self.file_link.clone()).desired_rows(3).desired_width(420.0).interactive(false));
                if ui.button("📋").clicked() {
                    ui.output_mut(|o| o.copied_text = self.file_link.clone());
                }
            });
        }
        ui.separator();
        ui.strong("Приём файла по ссылке:");
        ui.text_edit_singleline(&mut self.file_recv_link);
        if ui.button("⬇ Скачать").clicked() && !self.file_recv_link.is_empty() {
            if self.file_tx.is_none() {
                let (ev_tx, ev_rx) = channel::<FileEvent>();
                let (cmd_tx, cmd_rx) = channel::<FileCmd>();
                self.file_rx = Some(ev_rx);
                self.file_tx = Some(cmd_tx);
                std::thread::spawn(move || file_worker(ev_tx, cmd_rx));
            }
            if let Some(tx) = &self.file_tx {
                let _ = tx.send(FileCmd::Download(self.file_recv_link.trim().to_string()));
                self.file_status = "скачивание…".into();
            }
        }
        if !self.file_status.is_empty() {
            ui.colored_label(egui::Color32::LIGHT_GREEN, &self.file_status);
        }
        if let Some(tex) = &self.file_preview {
            ui.separator();
            ui.label(format!("🖼 Превью: {}", self.file_preview_name));
            let max_w = ui.available_width().min(420.0);
            let size = tex.size_vec2();
            let scale = (max_w / size.x).min(1.0);
            ui.image((tex.id(), size * scale));
        }
    }

    fn wallet(&self, ui: &mut egui::Ui) {
        ui.heading("Универсальный кошелёк");
        let seed = crypto::hex_decode(&self.seed_hex).unwrap_or_default();
        for (chain, path, addr) in [
            ("ETH", "m/44'/60'/0'/0/0", keytree::derive_path_secp256k1(&seed, "m/44'/60'/0'/0/0").and_then(|k| keytree::eth_address(&k.private))),
            ("BTC", "m/84'/0'/0'/0/0", keytree::derive_path_secp256k1(&seed, "m/84'/0'/0'/0/0").and_then(|k| keytree::btc_bech32_address(&k.private))),
            ("SOL", "m/44'/501'/0'/0'", keytree::sol_address(&seed, "m/44'/501'/0'/0'")),
            ("SMP", "m/0'/0'/0'", keytree::derive_path_ed25519(&seed, "m/0'/0'/0'").map(|k| {
                let sk = ed25519_dalek::SigningKey::from_bytes(&k.private);
                format!("ed25519:{}", crypto::base64url_encode(&sk.verifying_key().to_bytes()))
            })),
        ] {
            ui.label(format!("{chain}  {path}"));
            ui.monospace(addr.unwrap_or_else(|| "(недоступно)".into()));
            ui.add_space(6.0);
        }
    }

    fn fleet(&mut self, ui: &mut egui::Ui) {
        ui.heading("Удалённое управление флотом (NeXX — клиент, не нода)");
        ui.label("Те же ключи, что и на нодах Simplex/ParanoidX/NeXXus → тот же fleet. Ping — TCP до Local API ноды.");
        ui.add_space(8.0);
        let n = self.fleet.len();
        for i in 0..n {
            ui.horizontal(|ui| {
                ui.label(format!("node #{} id={}…", self.fleet[i].index, &self.fleet[i].id[..16]));
            });
            ui.horizontal(|ui| {
                ui.label("host:");
                ui.text_edit_singleline(&mut self.node_host[i]);
                ui.label("port:");
                if ui.button("Ping").clicked() {
                    let r = control::health_check_tcp(&self.node_host[i], 4010, 2500);
                    self.node_status[i] = if r["ok"].as_bool().unwrap_or(false) {
                        format!("🟢 online ({} ms)", r["latency_ms"])
                    } else {
                        "🔴 offline".into()
                    };
                }
                ui.label(&self.node_status[i]);
            });
            ui.separator();
        }
    }
}
