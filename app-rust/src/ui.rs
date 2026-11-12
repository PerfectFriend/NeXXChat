//! UI приложения NeXX: онбординг (BIP39) → кошелёк + удалённый флот нод.
//! Вся криптография — напрямую из nexxrust (rlib), никакого JNI.

use nexxrust::{bip39, control, crypto, keytree};

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
        }
    }

    pub fn ui(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| match self.phase {
            Phase::Onboarding => self.onboarding(ui),
            Phase::Main => self.main(ui),
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

    fn main(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Chats, "💬 Чаты");
            ui.selectable_value(&mut self.tab, Tab::Wallet, "💰 Кошелёк");
            ui.selectable_value(&mut self.tab, Tab::Fleet, "🖥️ Флот нод");
        });
        ui.separator();
        match self.tab {
            Tab::Chats => {
                ui.heading("Чаты");
                ui.label("SMP-транспорт поверх nexxrust::protocols — siguiente фаза. Здесь будет список контактов/чатов на ключе идентичности.");
                ui.label(format!("seed: {}…", &self.seed_hex[..16]));
            }
            Tab::Wallet => self.wallet(ui),
            Tab::Fleet => self.fleet(ui),
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
