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

/// Путь зашифрованного хранилища очередей (стандартная директория данных приложения).
fn queue_store_path() -> String {
    format!("{}/queues.bin", data_dir())
}

enum WorkerCmd {
    Send(String),
    Quit,
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
}

enum Phase {
    Onboarding,
    Main,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Chats,
    Contacts,
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
            ui.selectable_value(&mut self.tab, Tab::Wallet, "💰 Кошелёк");
            ui.selectable_value(&mut self.tab, Tab::Fleet, "🖥️ Флот нод");
        });
        ui.separator();
        match self.tab {
            Tab::Chats => self.chats(ui, ctx),
            Tab::Contacts => self.contacts_ui(ui),
            Tab::Wallet => self.wallet(ui),
            Tab::Fleet => self.fleet(ui),
        }
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
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
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
