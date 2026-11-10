#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Color32, RichText, Stroke};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};

const ACCENT: Color32 = Color32::from_rgb(70, 120, 235);
const OK: Color32 = Color32::from_rgb(90, 200, 120);
const ERR: Color32 = Color32::from_rgb(235, 90, 90);

#[derive(PartialEq, Clone, Copy)]
enum Kind {
    Info,
    Ok,
    Err,
}

struct App {
    file: Option<PathBuf>,
    file_size: Option<u64>,
    key: Option<PathBuf>,
    status: String,
    kind: Kind,
    busy: bool,
    last_out: Option<PathBuf>,
    tx: Sender<Result<String, String>>,
    rx: Receiver<Result<String, String>>,
}

fn ext_of(p: &Option<PathBuf>) -> String {
    p.as_ref()
        .and_then(|p| p.extension())
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase()
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| p.display().to_string())
}

fn human(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{:.1} {}", v, units[i])
    }
}

fn reveal(p: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg("-R").arg(p).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer")
            .arg(format!("/select,{}", p.display()))
            .spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(d) = p.parent() {
            let _ = std::process::Command::new("xdg-open").arg(d).spawn();
        }
    }
}

impl App {
    fn new() -> Self {
        let (tx, rx) = channel();
        Self {
            file: None,
            file_size: None,
            key: None,
            status: String::new(),
            kind: Kind::Info,
            busy: false,
            last_out: None,
            tx,
            rx,
        }
    }

    /// Route a picked/dropped path: keys go to the key slot, everything else is the file.
    fn set_input(&mut self, p: PathBuf) {
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if ext == "key" || ext == "pub" {
            self.key = Some(p);
        } else {
            self.file_size = std::fs::metadata(&p).map(|m| m.len()).ok();
            self.file = Some(p);
            self.status.clear();
            self.last_out = None;
        }
    }

    fn spawn(&mut self, ctx: &egui::Context, encrypt: bool) {
        let (Some(f), Some(k)) = (self.file.clone(), self.key.clone()) else {
            return;
        };
        self.busy = true;
        self.status.clear();
        self.last_out = None;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let f = f.to_string_lossy().to_string();
            let k = k.to_string_lossy().to_string();
            let r = if encrypt {
                pqe::encrypt(&f, &k)
            } else {
                pqe::decrypt(&f, &k)
            };
            let _ = tx.send(r.map_err(|e| e.to_string()));
            ctx.request_repaint();
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Results from the worker thread.
        while let Ok(r) = self.rx.try_recv() {
            self.busy = false;
            match r {
                Ok(m) => {
                    self.last_out = m.split_once(" -> ").map(|(_, p)| PathBuf::from(p));
                    self.status = m;
                    self.kind = Kind::Ok;
                }
                Err(e) => {
                    self.status = e;
                    self.kind = Kind::Err;
                    self.last_out = None;
                }
            }
        }

        // Drag and drop.
        let hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        for f in dropped {
            if let Some(p) = f.path {
                self.set_input(p);
            }
        }

        let decrypting = ext_of(&self.file) == "pqe";
        let key_ext = ext_of(&self.key);
        let key_mismatch = self.key.is_some()
            && if decrypting { key_ext == "pub" } else { key_ext == "key" };
        let ready = self.file.is_some() && self.key.is_some() && !self.busy && !key_mismatch;

        let frame = egui::Frame::none()
            .fill(ctx.style().visuals.panel_fill)
            .inner_margin(egui::Margin::same(22.0));

        egui::CentralPanel::default().frame(frame).show(ctx, |ui| {
            ui.label(RichText::new("Post-Quantum File Encryption").size(22.0).strong());
            ui.label(RichText::new("ML-KEM-768 + X25519 + AES-256-GCM").weak());
            ui.add_space(16.0);

            // Drop zone
            let (rect, resp) = ui.allocate_exact_size(
                egui::vec2(ui.available_width(), 120.0),
                egui::Sense::click(),
            );
            let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
            let (fill, stroke) = if hovering {
                (
                    Color32::from_rgba_unmultiplied(70, 120, 235, 40),
                    Stroke::new(2.0, ACCENT),
                )
            } else {
                (
                    ui.visuals().extreme_bg_color,
                    Stroke::new(1.0, ui.visuals().widgets.noninteractive.bg_stroke.color),
                )
            };
            ui.painter().rect(rect, 10.0, fill, stroke);

            let text_color = ui.visuals().text_color();
            let weak_color = ui.visuals().weak_text_color();
            let (main, sub) = if hovering {
                ("Release to add".to_string(), String::new())
            } else if let Some(p) = &self.file {
                let size = self.file_size.map(human).unwrap_or_default();
                let mode = if decrypting { "Ready to decrypt" } else { "Ready to encrypt" };
                (file_name(p), format!("{size}  -  {mode}  -  click to change"))
            } else {
                (
                    "Drop a file here".to_string(),
                    "or click to choose one (any file type)".to_string(),
                )
            };
            ui.painter().text(
                rect.center() - egui::vec2(0.0, 10.0),
                egui::Align2::CENTER_CENTER,
                main,
                egui::FontId::proportional(18.0),
                text_color,
            );
            ui.painter().text(
                rect.center() + egui::vec2(0.0, 16.0),
                egui::Align2::CENTER_CENTER,
                sub,
                egui::FontId::proportional(13.0),
                weak_color,
            );
            if resp.clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    self.set_input(p);
                }
            }

            ui.add_space(14.0);

            // Key
            ui.label(
                RichText::new(if decrypting {
                    "Your private key (.key)"
                } else {
                    "Public key (.pub)"
                })
                .strong(),
            );
            ui.horizontal(|ui| {
                if ui.button("Choose key...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.key = Some(p);
                    }
                }
                match &self.key {
                    Some(p) => ui.label(file_name(p)),
                    None => ui.label(RichText::new("none chosen").weak()),
                };
            });
            if key_mismatch {
                ui.colored_label(
                    ERR,
                    if decrypting {
                        "That is a public key. Decrypting needs your private .key file."
                    } else {
                        "That is a private key. Encrypting needs a public .pub file."
                    },
                );
            }

            ui.add_space(14.0);

            // Action
            let label = if decrypting { "Decrypt" } else { "Encrypt" };
            let btn = egui::Button::new(
                RichText::new(label).size(16.0).strong().color(Color32::WHITE),
            )
            .fill(ACCENT)
            .min_size(egui::vec2(ui.available_width(), 40.0));
            if ui.add_enabled(ready, btn).clicked() {
                self.spawn(ctx, !decrypting);
            }

            ui.add_space(10.0);

            // Status
            if self.busy {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Working...");
                });
            } else if !self.status.is_empty() {
                let color = match self.kind {
                    Kind::Ok => OK,
                    Kind::Err => ERR,
                    Kind::Info => ui.visuals().text_color(),
                };
                ui.colored_label(color, &self.status);
                if let Some(p) = self.last_out.clone() {
                    if ui.button("Show in folder").clicked() {
                        reveal(&p);
                    }
                }
            }

            ui.add_space(12.0);
            ui.separator();

            // Keys section
            egui::CollapsingHeader::new("Keys")
                .default_open(self.key.is_none())
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(
                            "Make a key pair once. Share the .pub, and keep the .key secret and backed up.",
                        )
                        .weak(),
                    );
                    ui.add_space(4.0);
                    if ui
                        .add_enabled(!self.busy, egui::Button::new("Generate new key pair..."))
                        .clicked()
                    {
                        if let Some(path) =
                            rfd::FileDialog::new().set_file_name("mykey").save_file()
                        {
                            let name = path.to_string_lossy().to_string();
                            match pqe::keygen(&name) {
                                Ok(m) => {
                                    self.status = m;
                                    self.kind = Kind::Ok;
                                }
                                Err(e) => {
                                    self.status = e.to_string();
                                    self.kind = Kind::Err;
                                }
                            }
                            self.last_out = None;
                        }
                    }
                });
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 600.0])
            .with_min_inner_size([520.0, 520.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "pqe",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(App::new()))
        }),
    )
}
