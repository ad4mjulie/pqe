#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};

struct App {
    file: Option<PathBuf>,
    key: Option<PathBuf>,
    status: String,
    busy: bool,
    tx: Sender<String>,
    rx: Receiver<String>,
}

impl App {
    fn new() -> Self {
        let (tx, rx) = channel();
        Self {
            file: None,
            key: None,
            status: "Drop a file onto this window, or use the buttons.".into(),
            busy: false,
            tx,
            rx,
        }
    }

    fn is_encrypted(&self) -> bool {
        self.file
            .as_ref()
            .and_then(|p| p.extension())
            .map(|e| e == "pqe")
            .unwrap_or(false)
    }

    fn spawn(&mut self, ctx: &egui::Context, encrypt: bool) {
        let (Some(f), Some(k)) = (self.file.clone(), self.key.clone()) else {
            self.status = "Choose a file and a key first.".into();
            return;
        };
        self.busy = true;
        self.status = "Working...".into();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let f = f.to_string_lossy().to_string();
            let k = k.to_string_lossy().to_string();
            let r = if encrypt { pqe::encrypt(&f, &k) } else { pqe::decrypt(&f, &k) };
            let msg = match r {
                Ok(m) => m,
                Err(e) => format!("Error: {e}"),
            };
            let _ = tx.send(msg);
            ctx.request_repaint();
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(msg) = self.rx.try_recv() {
            self.status = msg;
            self.busy = false;
        }
        if let Some(p) = ctx.input(|i| i.raw.dropped_files.first().and_then(|f| f.path.clone())) {
            self.file = Some(p);
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Post-Quantum File Encryption");
            ui.label("ML-KEM-768 + X25519 + AES-256-GCM");
            ui.separator();

            ui.label("1. Keys (do this once)");
            if ui.add_enabled(!self.busy, egui::Button::new("Generate new key pair...")).clicked() {
                if let Some(path) = rfd::FileDialog::new().set_file_name("mykey").save_file() {
                    let name = path.to_string_lossy().to_string();
                    self.status = match pqe::keygen(&name) {
                        Ok(m) => m,
                        Err(e) => format!("Error: {e}"),
                    };
                }
            }
            ui.separator();

            ui.label("2. File (any type; drag and drop works)");
            ui.horizontal(|ui| {
                if ui.button("Choose file...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.file = Some(p);
                    }
                }
                ui.label(self.file.as_ref().map(|p| p.display().to_string()).unwrap_or("none".into()));
            });

            let decrypting = self.is_encrypted();
            ui.label(if decrypting {
                "3. Your PRIVATE key (.key) to decrypt"
            } else {
                "3. Your PUBLIC key (.pub) to encrypt"
            });
            ui.horizontal(|ui| {
                if ui.button("Choose key...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.key = Some(p);
                    }
                }
                ui.label(self.key.as_ref().map(|p| p.display().to_string()).unwrap_or("none".into()));
            });
            ui.separator();

            ui.horizontal(|ui| {
                if ui.add_enabled(!self.busy && !decrypting, egui::Button::new("Encrypt")).clicked() {
                    self.spawn(ctx, true);
                }
                if ui.add_enabled(!self.busy && decrypting, egui::Button::new("Decrypt")).clicked() {
                    self.spawn(ctx, false);
                }
                if self.busy {
                    ui.spinner();
                }
            });
            ui.add_space(8.0);
            ui.label(&self.status);
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([560.0, 380.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "pqe",
        options,
        Box::new(|_cc| Ok(Box::new(App::new()))),
    )
}
