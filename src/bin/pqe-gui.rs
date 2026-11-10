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

#[derive(Clone, Copy)]
enum Slot {
    Input,
    Key,
    Sign,
    Verify,
}

enum Msg {
    Work(Result<String, String>),
    Picked(Slot, PathBuf),
    DialogClosed,
}

enum Pick {
    Input,
    Folder,
    Key,
    Sign,
    Verify,
    SaveKeys(Option<String>),
}

struct App {
    file: Option<PathBuf>,
    file_size: Option<u64>,
    file_is_dir: bool,
    key: Option<PathBuf>,
    key_locked: bool,
    sign_on: bool,
    sign_key: Option<PathBuf>,
    sign_locked: bool,
    verify_vk: Option<PathBuf>,
    password: String,
    new_pw_on: bool,
    new_pw1: String,
    new_pw2: String,
    status: String,
    kind: Kind,
    busy: bool,
    last_out: Option<PathBuf>,
    dialog_open: bool,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
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

fn path_str(p: &Path) -> String {
    p.to_string_lossy().to_string()
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
            file_is_dir: false,
            key: None,
            key_locked: false,
            sign_on: false,
            sign_key: None,
            sign_locked: false,
            verify_vk: None,
            password: String::new(),
            new_pw_on: false,
            new_pw1: String::new(),
            new_pw2: String::new(),
            status: String::new(),
            kind: Kind::Info,
            busy: false,
            last_out: None,
            dialog_open: false,
            tx,
            rx,
        }
    }

    /// Route a picked/dropped path: keys and verify-keys go to their slots, the rest is the input.
    fn set_input(&mut self, p: PathBuf) {
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let is_dir = p.is_dir();
        if !is_dir && (ext == "key" || ext == "pub") {
            self.key_locked = pqe::key_is_protected(&path_str(&p));
            self.key = Some(p);
            self.password.clear();
        } else if !is_dir && ext == "vk" {
            self.verify_vk = Some(p);
        } else {
            self.file_size = if is_dir {
                None
            } else {
                std::fs::metadata(&p).map(|m| m.len()).ok()
            };
            self.file_is_dir = is_dir;
            self.file = Some(p);
            self.status.clear();
            self.last_out = None;
        }
    }

    /// File dialogs run on a worker thread so macOS never re-enters the UI loop.
    fn open_dialog(&mut self, ctx: &egui::Context, what: Pick) {
        if self.dialog_open {
            return;
        }
        self.dialog_open = true;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            match what {
                Pick::Input => {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        let _ = tx.send(Msg::Picked(Slot::Input, p));
                    }
                }
                Pick::Folder => {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        let _ = tx.send(Msg::Picked(Slot::Input, p));
                    }
                }
                Pick::Key => {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        let _ = tx.send(Msg::Picked(Slot::Key, p));
                    }
                }
                Pick::Sign => {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        let _ = tx.send(Msg::Picked(Slot::Sign, p));
                    }
                }
                Pick::Verify => {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        let _ = tx.send(Msg::Picked(Slot::Verify, p));
                    }
                }
                Pick::SaveKeys(pw) => {
                    if let Some(p) = rfd::FileDialog::new().set_file_name("mykey").save_file() {
                        let r = pqe::keygen(&path_str(&p), pw.as_deref()).map_err(|e| e.to_string());
                        let _ = tx.send(Msg::Work(r));
                    }
                }
            }
            let _ = tx.send(Msg::DialogClosed);
            ctx.request_repaint();
        });
    }

    fn spawn(&mut self, ctx: &egui::Context, encrypt: bool) {
        let (Some(f), Some(k)) = (self.file.clone(), self.key.clone()) else {
            return;
        };
        let pw = if self.password.is_empty() {
            None
        } else {
            Some(self.password.clone())
        };
        let sign = if encrypt && self.sign_on {
            self.sign_key.clone()
        } else {
            None
        };
        let verify = self.verify_vk.clone();
        self.busy = true;
        self.status.clear();
        self.last_out = None;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let f = path_str(&f);
            let k = path_str(&k);
            let r = if encrypt {
                let opts = sign.map(|p| pqe::SignOpts {
                    key_path: path_str(&p),
                    password: pw.clone(),
                });
                pqe::encrypt(&f, &k, opts)
            } else {
                let v = verify.map(|p| path_str(&p));
                pqe::decrypt(&f, &k, pw.as_deref(), v.as_deref())
            };
            let _ = tx.send(Msg::Work(r.map_err(|e| e.to_string())));
            ctx.request_repaint();
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Messages from worker threads.
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Work(r) => {
                    self.busy = false;
                    match r {
                        Ok(m) => {
                            let first = m.lines().next().unwrap_or("").to_string();
                            self.last_out = first.split_once(" -> ").map(|(_, p)| PathBuf::from(p));
                            self.status = m;
                            self.kind = Kind::Ok;
                            self.password.clear();
                        }
                        Err(e) => {
                            self.status = e;
                            self.kind = Kind::Err;
                            self.last_out = None;
                        }
                    }
                }
                Msg::Picked(slot, p) => match slot {
                    Slot::Input => self.set_input(p),
                    Slot::Key => {
                        self.key_locked = pqe::key_is_protected(&path_str(&p));
                        self.key = Some(p);
                        self.password.clear();
                    }
                    Slot::Sign => {
                        self.sign_locked = pqe::key_is_protected(&path_str(&p));
                        self.sign_key = Some(p);
                        self.password.clear();
                    }
                    Slot::Verify => self.verify_vk = Some(p),
                },
                Msg::DialogClosed => self.dialog_open = false,
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

        let decrypting = ext_of(&self.file) == "pqe" && !self.file_is_dir;
        let key_ext = ext_of(&self.key);
        let key_mismatch = self.key.is_some()
            && if decrypting { key_ext == "pub" } else { key_ext == "key" };
        let need_pw = if decrypting {
            self.key_locked
        } else {
            self.sign_on && self.sign_locked
        };
        let pw_ok = !need_pw || !self.password.is_empty();
        let sign_ok = decrypting || !self.sign_on || self.sign_key.is_some();
        let ready = self.file.is_some()
            && self.key.is_some()
            && !self.busy
            && !key_mismatch
            && pw_ok
            && sign_ok;

        let frame = egui::Frame::none()
            .fill(ctx.style().visuals.panel_fill)
            .inner_margin(egui::Margin::same(22.0));

        egui::CentralPanel::default().frame(frame).show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
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
                    let what = if self.file_is_dir {
                        "Folder".to_string()
                    } else {
                        self.file_size.map(human).unwrap_or_default()
                    };
                    let mode = if decrypting { "Ready to decrypt" } else { "Ready to encrypt" };
                    (file_name(p), format!("{what}  -  {mode}  -  click to change"))
                } else {
                    (
                        "Drop a file or folder here".to_string(),
                        "or click to choose a file".to_string(),
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
                    self.open_dialog(ctx, Pick::Input);
                }
                ui.add_space(6.0);
                if ui.button("Choose folder...").clicked() {
                    self.open_dialog(ctx, Pick::Folder);
                }

                ui.add_space(12.0);

                // Main key
                ui.label(
                    RichText::new(if decrypting {
                        "Your private key (.key)"
                    } else {
                        "Public key to encrypt to (.pub)"
                    })
                    .strong(),
                );
                ui.horizontal(|ui| {
                    if ui.button("Choose key...").clicked() {
                        self.open_dialog(ctx, Pick::Key);
                    }
                    match &self.key {
                        Some(p) => {
                            ui.label(file_name(p));
                            if decrypting && self.key_locked {
                                ui.label(RichText::new("password-protected").weak());
                            }
                        }
                        None => {
                            ui.label(RichText::new("none chosen").weak());
                        }
                    }
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

                ui.add_space(10.0);

                // Mode-specific options
                if decrypting {
                    ui.label(RichText::new("Verify the sender (optional)").strong());
                    ui.horizontal(|ui| {
                        if ui.button("Choose sender's .vk...").clicked() {
                            self.open_dialog(ctx, Pick::Verify);
                        }
                        match self.verify_vk.clone() {
                            Some(p) => {
                                ui.label(file_name(&p));
                                if ui.button("Clear").clicked() {
                                    self.verify_vk = None;
                                }
                            }
                            None => {
                                ui.label(RichText::new("not checking who sent it").weak());
                            }
                        }
                    });
                } else {
                    ui.checkbox(&mut self.sign_on, "Sign this with my key (proves it came from me)");
                    if self.sign_on {
                        ui.horizontal(|ui| {
                            if ui.button("Choose my .key...").clicked() {
                                self.open_dialog(ctx, Pick::Sign);
                            }
                            match &self.sign_key {
                                Some(p) => {
                                    ui.label(file_name(p));
                                    if self.sign_locked {
                                        ui.label(RichText::new("password-protected").weak());
                                    }
                                }
                                None => {
                                    ui.label(RichText::new("none chosen").weak());
                                }
                            }
                        });
                    }
                }

                if need_pw {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Key password").strong());
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password)
                            .password(true)
                            .hint_text("Enter the password for that key")
                            .desired_width(f32::INFINITY),
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
                                "Make a key set once: .pub (people encrypt to it), .vk (people verify your signatures), .key (secret, back it up).",
                            )
                            .weak(),
                        );
                        ui.add_space(4.0);
                        ui.checkbox(&mut self.new_pw_on, "Protect the new private key with a password");
                        if self.new_pw_on {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_pw1)
                                    .password(true)
                                    .hint_text("New password")
                                    .desired_width(f32::INFINITY),
                            );
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_pw2)
                                    .password(true)
                                    .hint_text("Repeat password")
                                    .desired_width(f32::INFINITY),
                            );
                        }
                        ui.add_space(4.0);
                        if ui
                            .add_enabled(!self.busy, egui::Button::new("Generate new key set..."))
                            .clicked()
                        {
                            if self.new_pw_on && (self.new_pw1.is_empty() || self.new_pw1 != self.new_pw2) {
                                self.status =
                                    "Passwords are empty or do not match. Fix them, then try again."
                                        .to_string();
                                self.kind = Kind::Err;
                                self.last_out = None;
                            } else {
                                let pw = if self.new_pw_on {
                                    Some(self.new_pw1.clone())
                                } else {
                                    None
                                };
                                self.new_pw1.clear();
                                self.new_pw2.clear();
                                self.open_dialog(ctx, Pick::SaveKeys(pw));
                            }
                        }
                    });
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([620.0, 720.0])
            .with_min_inner_size([540.0, 560.0])
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