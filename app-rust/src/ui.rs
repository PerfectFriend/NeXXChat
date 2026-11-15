//! UI приложения NeXX: онбординг (BIP39) → чат (SMP live) + кошелёк + флот нод.
//! Вся криптография — напрямую из nexxrust (rlib), никакого JNI.
//! Раскладка как в Telegram: слева список чатов, справа переписка, ввод снизу.

use nexxrust::{bip39, control, crypto, keytree};
use nexxrust::protocols::smp;
use nexxrust::protocols::smp_client::SmpClient;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// CA-цепочка публичных SMP-релеев SimpleX (публичные сертификаты, пиннинг как в smp_smoke).
const SMP_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBwjCCAUKgAwIBAgIUJIHRXfsIlUWgHKVAYWnhd0ghJMgwBQYDK2VxMCoxFjAU
BgNVBAMMDVNNUCBzZXJ2ZXIgQ0ExEDAOBgNVBAoMB1NpbXBsZVgwIBcNMjYwMTA1
MDkzMzQ5WhgPNDc2MzEyMDIwOTMzNDlaMBoxGDAWBgNVBAMMD3NtcDYuc2ltcGxl
eC5pbTBDMAUGAytlcQM6AD51xMggRBOdV2mGLTTrrVPgDk5lKXjSdLvVH4XJd0qc
fVGrJiwV5W/ZUZG+wmX7LzRMC37oS/0xAKNvMG0wCQYDVR0TBAIwADALBgNVHQ8E
BAMCA8gwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFCb01tgTLSY1/tqO
WoAahpSKY2TNMB8GA1UdIwQYMBaAFKwAnLeCqJPRrZZpDIJ9MnZSOp3nMAUGAytl
cQNzAOQ7FbPs6IzPSNUxZ7QLtzG5Nb/60rzi73vEa8sZu9kn/F8uE8OiWd15qs+V
fVOWOsPjPDd7zT0mAMgSxdJJ7vtnR7kejsA3bNqAr+zfX3k3mHzkKsCtxjht4EcR
tpLCTwm7NSk9HSgWsMfzJQB2vicPAA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBtjCCATagAwIBAgIUUyW5oE/0cm3BhQUtU1poneSoxvgwBQYDK2VxMCoxFjAU
BgNVBAMMDVNNUCBzZXJ2ZXIgQ0ExEDAOBgNVBAoMB1NpbXBsZVgwIBcNMjIwMTEy
MTE0ODUwWhgPNDc1OTEyMDkxMTQ4NTBaMCoxFjAUBgNVBAMMDVNNUCBzZXJ2ZXIg
Q0ExEDAOBgNVBAoMB1NpbXBsZVgwQzAFBgMrZXEDOgA9fWFWCQZmSm07M0LyYJ8a
PnAZBv/vy+rZrLPG7dQ9xTFKpCrIZA8X2gzQCdyaGQVvZsE/zgcq7YCjUzBRMB0G
A1UdDgQWBBSsAJy3gqiT0a2WaQyCfTJ2Ujqd5zAfBgNVHSMEGDAWgBSsAJy3gqiT
0a2WaQyCfTJ2Ujqd5zAPBgNVHRMBAf8EBTADAQH/MAUGAytlcQNzAM+etlcjuA4R
DfYAQmYwtYptS3IrzQ5QVjEG7sOx/tPVJyKE1gYJviquIKJml2dJLshf5kY58DH/
gNmbtPkDMwoWl/2g0NKyY/UA4qOLVNxQtiW8cMR+bGpGaUuupdL19xygH5lhftuc
UjjdUuav0c4jAA==
-----END CERTIFICATE-----";

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
    seed: Vec<u8>,
    ev: Sender<ChatEvent>,
    cmd: Receiver<WorkerCmd>,
) {
    let say = |e: ChatEvent| { let _ = ev.send(e); };
    say(ChatEvent::Status("TLS connect…".into()));
    let mut client = match SmpClient::connect_openssl_with_ca(&host, port, Some(SMP_CA_PEM)) {
        Ok(c) => c,
        Err(e) => return say(ChatEvent::Err(format!("connect: {e}"))),
    };
    // Неблокирующий poll: иначе recv_transmissions ждёт до 60 с и команды Send из UI встают в очередь.
    client.set_read_timeout(Some(Duration::from_millis(400)));
    let auth = match keytree::derive_path_ed25519(&seed, "m/0'/0'/0'") {
        Some(k) => ed25519_dalek::SigningKey::from_bytes(&k.private),
        None => return say(ChatEvent::Err("keytree derive failed".into())),
    };
    let dh = match keytree::derive_path_ed25519(&seed, "m/0'/0'/1'") {
        Some(k) => StaticSecret::from(k.private),
        None => return say(ChatEvent::Err("keytree dh failed".into())),
    };
    say(ChatEvent::Status("NEW queue…".into()));
    let ids = match client.create_queue(&smp::RecipientKeys { auth_signing: auth.clone(), dh_secret: dh.clone() }) {
        Ok(i) => i,
        Err(e) => return say(ChatEvent::Err(format!("NEW: {e}"))),
    };
    let eph_bytes: [u8; 32] = crypto::random_bytes(32).try_into().unwrap();
    let eph = StaticSecret::from(eph_bytes);
    let eph_pub_x509 = smp::x25519_x509(X25519Public::from(&eph).as_bytes());
    let e2e = eph.diffie_hellman(&X25519Public::from(&dh));
    let srv_pub = match smp::parse_x25519_x509(&ids.srv_dh_x509) {
        Some(p) => p,
        None => return say(ChatEvent::Err("bad srv dh key".into())),
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
                WorkerCmd::Quit => return,
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
            Err(e) => say(ChatEvent::Err(format!("recv: {e}"))),
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
}

enum Phase {
    Onboarding,
    Main,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Chats,
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
            ui.text_edit_multiline(&mut self.mnemonic_input);
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
            ui.selectable_value(&mut self.tab, Tab::Wallet, "💰 Кошелёк");
            ui.selectable_value(&mut self.tab, Tab::Fleet, "🖥️ Флот нод");
        });
        ui.separator();
        match self.tab {
            Tab::Chats => self.chats(ui, ctx),
            Tab::Wallet => self.wallet(ui),
            Tab::Fleet => self.fleet(ui),
        }
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
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.chat_host);
                        ui.add(egui::DragValue::new(&mut self.chat_port).range(443..=65535));
                    });
                    if ui.button("Подключиться").clicked() {
                        let seed = crypto::hex_decode(&self.seed_hex).unwrap_or_default();
                        let (ev_tx, ev_rx) = channel::<ChatEvent>();
                        let (cmd_tx, cmd_rx) = channel::<WorkerCmd>();
                        self.chat_rx = Some(ev_rx);
                        self.chat_tx = Some(cmd_tx);
                        self.chat_status = "connecting…".into();
                        let host = self.chat_host.clone();
                        let port = self.chat_port;
                        std::thread::spawn(move || chat_worker(host, port, seed, ev_tx, cmd_rx));
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
