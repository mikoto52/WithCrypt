#![forbid(unsafe_code)]
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
//! WithCrypt desktop app (egui). One `Desktop` state drives two windows:
//! - the main window: encrypt / decrypt / verify, with native save dialogs;
//! - the compact Explorer-menu window (`--encrypt` / `--decrypt <file>`), which
//!   saves next to the input without asking.
//!
//! File work always runs on a background thread through the core `files` API.
use eframe::egui;
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};
use withcrypt_core::{
    Header, Progress, Stage, Suite, Summary,
    files::{self, Operation},
};
use zeroize::{Zeroize, Zeroizing};

/// The three operations offered by the main window.
#[derive(Default, PartialEq, Clone, Copy)]
enum Mode {
    #[default]
    Encrypt,
    Decrypt,
    Verify,
}
/// What a background job hands back to the UI thread.
enum WorkerResult {
    Prepared(Box<files::PreparedDecryption>),
    Complete(Summary),
}
/// A running background job. The UI polls `result` every frame, reads the
/// latest `progress`, and sets `cancel` to ask the job to stop.
struct Worker {
    cancel: Arc<AtomicBool>,
    progress: Arc<Mutex<Progress>>,
    /// Expected plaintext bytes for the percentage; 0 when unknown.
    total: u64,
    result: mpsc::Receiver<withcrypt_core::Result<WorkerResult>>,
    handle: thread::JoinHandle<()>,
}
#[derive(Default)]
/// All UI state. Secrets live in `Zeroizing` buffers and are wiped as soon
/// as a job takes them or the user cancels.
struct Desktop {
    mode: Mode,
    suite: Suite,
    /// Path text shown in, and typed into, the input field.
    input: String,
    /// Exact path from the file picker. Kept separately because `input` is a
    /// display string and would lose non-UTF-8 paths.
    selected_input: Option<PathBuf>,
    password: Zeroizing<String>,
    /// Password confirmation buffer (no field shows it now); wiped with `password`.
    confirmation: Zeroizing<String>,
    show_password: bool,
    /// Algorithm read from the (not yet authenticated) header, for display only.
    preview: String,
    /// Last result or error shown in the status area.
    message: String,
    worker: Option<Worker>,
    /// Decryption whose filename is authenticated, waiting for a save location.
    prepared: Option<Box<files::PreparedDecryption>>,
    /// The window was closed during a job; close for real once it has stopped.
    closing: bool,
    /// App icon texture, uploaded on the first frame.
    logo: Option<egui::TextureHandle>,
    /// Launched from the Explorer menu: no destination dialog, save beside the input.
    shell: bool,
}
impl Desktop {
    /// The file to operate on: the picked path if any, else the typed text.
    fn input_path(&self) -> PathBuf {
        self.selected_input
            .clone()
            .unwrap_or_else(|| self.input.clone().into())
    }
    /// Reads the 64-byte header of the selected file to show its algorithm.
    /// This happens before any password check, so the UI labels it unauthenticated.
    fn preview_header(&mut self) {
        self.preview = String::new();
        if self.mode == Mode::Encrypt || self.input.is_empty() {
            return;
        }
        let read = (|| {
            let mut file = std::fs::File::open(self.input_path()).ok()?;
            if !file.metadata().ok()?.is_file() {
                return None;
            }
            let mut raw = [0; 64];
            file.read_exact(&mut raw).ok()?;
            Header::parse(raw).ok()
        })();
        self.preview = read
            .map(|h| format!("{} · 아직 인증되지 않은 헤더", h.suite.name()))
            .unwrap_or_else(|| "ESB 헤더를 읽을 수 없습니다".into());
    }
    /// Main window: native save dialog prefilled with the suggested name.
    fn choose_save(input: &Path, filename: &str, encrypted: bool) -> Option<PathBuf> {
        let mut dialog = rfd::FileDialog::new()
            .set_title(if encrypted {
                "암호화 파일 저장"
            } else {
                "복호화 파일 저장"
            })
            .set_directory(input.parent().unwrap_or(Path::new(".")))
            .set_file_name(filename);
        if encrypted {
            dialog = dialog.add_filter("ESB", &["esb"]);
        }
        dialog.save_file()
    }
    /// Explorer-menu window: no dialog, the result goes next to the input file.
    fn beside_input(input: &Path, filename: &str, _encrypted: bool) -> Option<PathBuf> {
        Some(input.parent()?.join(filename))
    }
    /// Where results are saved, depending on how the app was launched.
    fn chooser(&self) -> fn(&Path, &str, bool) -> Option<PathBuf> {
        if self.shell {
            Self::beside_input
        } else {
            Self::choose_save
        }
    }
    /// State for an Explorer-menu launch on `path`.
    fn for_shell(mode: Mode, path: PathBuf) -> Self {
        let path = std::path::absolute(&path).unwrap_or(path);
        let mut app = Self::default();
        app.mode = mode;
        app.shell = true;
        app.input = path.to_string_lossy().into_owned();
        app.selected_input = Some(path);
        app.preview_header();
        app
    }
    /// Starts the selected operation (start button or Enter).
    fn start(&mut self, ctx: &egui::Context) {
        let mut choose = self.chooser();
        self.start_with_chooser(ctx, &mut choose);
    }
    /// `start` with an injectable save-location chooser, so tests avoid native
    /// dialogs. Decrypt only runs its first half here (key derivation and the
    /// stored filename); the save location is chosen afterwards in `save_prepared`.
    fn start_with_chooser(
        &mut self,
        ctx: &egui::Context,
        choose: &mut impl FnMut(&Path, &str, bool) -> Option<PathBuf>,
    ) {
        if self.worker.is_some() || self.prepared.is_some() {
            return;
        }
        if self.input.is_empty() {
            self.message = "입력 파일을 지정하세요.".into();
            return;
        }
        if self.password.is_empty() {
            self.message = "비밀번호를 입력하세요.".into();
            return;
        }
        let input = match std::fs::canonicalize(self.input_path()) {
            Ok(path) => path,
            Err(e) => {
                self.message = e.to_string();
                return;
            }
        };
        let output = if self.mode == Mode::Encrypt {
            let default = match files::encrypted_path(&input) {
                Ok(path) => path,
                Err(e) => {
                    self.message = e.to_string();
                    return;
                }
            };
            let name = default.file_name().unwrap_or_default().to_string_lossy();
            match choose(&input, &name, true) {
                Some(path) => Some(path),
                None => {
                    self.cancel_selection();
                    return;
                }
            }
        } else {
            None
        };
        let mode = self.mode;
        let suite = self.suite;
        let total = expected_total(mode, &input);
        // Move the password into the job; the UI keeps no copy while it runs.
        let password = std::mem::take(&mut self.password);
        self.confirmation.zeroize();
        self.show_password = false;
        self.spawn_work(ctx, total, move |observer| match mode {
            Mode::Decrypt => files::prepare_decryption(&input, password.as_bytes(), observer)
                .map(|prepared| WorkerResult::Prepared(Box::new(prepared))),
            Mode::Encrypt => files::run(
                &input,
                output.as_deref(),
                password.as_bytes(),
                Operation::Encrypt(suite),
                observer,
            )
            .map(WorkerResult::Complete),
            Mode::Verify => files::run(
                &input,
                None,
                password.as_bytes(),
                Operation::Verify,
                observer,
            )
            .map(WorkerResult::Complete),
        });
    }
    /// The user dismissed the save dialog: wipe the password and create nothing.
    fn cancel_selection(&mut self) {
        self.password.zeroize();
        self.confirmation.zeroize();
        self.show_password = false;
        self.message = "저장을 취소했습니다. 출력 파일을 만들지 않았습니다.".into();
    }
    /// Second half of decryption: once the filename is authenticated, choose the
    /// output path and run full decryption and verification in the background.
    fn save_prepared(
        &mut self,
        ctx: &egui::Context,
        choose: &mut impl FnMut(&Path, &str, bool) -> Option<PathBuf>,
    ) {
        let Some(prepared) = self.prepared.take() else {
            return;
        };
        if self.closing {
            return;
        }
        let name = if prepared.filename().is_empty() {
            "decrypted.bin"
        } else {
            prepared.filename()
        };
        // Only authenticated META names reach the native dialog. Full validation follows.
        let Some(output) = choose(&self.input_path(), name, false) else {
            self.cancel_selection();
            return;
        };
        let total = expected_total(Mode::Decrypt, &self.input_path());
        self.spawn_work(ctx, total, move |observer| {
            prepared.save(&output, observer).map(WorkerResult::Complete)
        });
    }
    /// Runs `job` on a worker thread. Progress is kept in a shared slot holding
    /// only the latest value (a fast job cannot flood the UI); the result comes
    /// back through a channel.
    fn spawn_work(
        &mut self,
        ctx: &egui::Context,
        total: u64,
        job: impl FnOnce(&mut withcrypt_core::Observer<'_>) -> withcrypt_core::Result<WorkerResult>
        + Send
        + 'static,
    ) {
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let progress = Arc::new(Mutex::new(Progress {
            stage: Stage::Kdf,
            bytes: 0,
        }));
        let shared = progress.clone();
        let (tx, rx) = mpsc::channel();
        let context = ctx.clone();
        // The observer stores progress, wakes the UI, and answers "stop" once
        // cancel is set.
        let handle = thread::spawn(move || {
            let result = job(&mut |p| {
                if let Ok(mut value) = shared.lock() {
                    *value = p;
                }
                context.request_repaint();
                !flag.load(Ordering::Relaxed)
            });
            let _ = tx.send(result);
            context.request_repaint();
        });
        self.worker = Some(Worker {
            cancel,
            progress,
            total,
            result: rx,
            handle,
        });
        self.message.clear();
    }
    /// Called every frame: collects a finished job and turns its result into a message.
    fn poll(&mut self) {
        let result = self
            .worker
            .as_ref()
            .and_then(|w| match w.result.try_recv() {
                Ok(r) => Some(r),
                // The worker ended without reporting (for example, it panicked).
                Err(mpsc::TryRecvError::Disconnected) => Some(Err(withcrypt_core::Error::Resource)),
                Err(mpsc::TryRecvError::Empty) => None,
            });
        if let Some(result) = result {
            let cancelled = if let Some(worker) = self.worker.take() {
                let cancelled = worker.cancel.load(Ordering::Relaxed);
                let _ = worker.handle.join();
                cancelled
            } else {
                false
            };
            self.message = match result {
                Ok(WorkerResult::Prepared(prepared)) => {
                    if cancelled || self.closing {
                        "사용자가 취소했습니다".into()
                    } else {
                        self.prepared = Some(prepared);
                        "원본 파일명 인증 완료 · 저장 위치 선택 후 전체 파일을 검증합니다".into()
                    }
                }
                Ok(WorkerResult::Complete(s)) => format!(
                    "완료 · {} 바이트 · {}{}",
                    s.original_size,
                    s.suite.name(),
                    if self.mode == Mode::Encrypt && s.filename.is_empty() {
                        " · 이식 불가능한 파일명 메타데이터는 생략했습니다"
                    } else {
                        ""
                    }
                ),
                Err(e) => e.to_string(),
            };
        }
    }
}
/// Never leave a job running when the app exits: cancel it and wait for it.
impl Drop for Desktop {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.cancel.store(true, Ordering::Relaxed);
            let _ = worker.handle.join();
        }
    }
}
impl eframe::App for Desktop {
    /// One frame: handle close requests, advance the decrypt flow, draw the UI.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        let ctx = ui.ctx().clone();
        // Closing during a job: keep the window open until the job has stopped
        // cleanly, so no partial output is left behind.
        if ctx.input(|i| i.viewport().close_requested())
            && (self.worker.is_some() || self.prepared.is_some())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.closing = true;
            if let Some(w) = &self.worker {
                w.cancel.store(true, Ordering::Relaxed);
            }
        }
        let mut choose = self.chooser();
        // As soon as a decrypt has authenticated its filename, ask where to save.
        self.save_prepared(&ctx, &mut choose);
        if self.closing && self.worker.is_none() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        let pal = Palette::of(ui.visuals().dark_mode);
        // Upload the app icon once; mipmaps keep the downscaled logo smooth.
        if self.logo.is_none()
            && let Ok(icon) = eframe::icon_data::from_png_bytes(LOGO)
        {
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [icon.width as usize, icon.height as usize],
                &icon.rgba,
            );
            let options = egui::TextureOptions {
                mipmap_mode: Some(egui::TextureFilter::Linear),
                ..egui::TextureOptions::LINEAR
            };
            self.logo = Some(ctx.load_texture("logo", image, options));
        }
        if self.shell {
            // Explorer-menu launches get the compact window instead.
            self.shell_ui(ui, &ctx, &pal);
            return;
        }
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(pal.bg)
                    .inner_margin(egui::Margin::symmetric(28, 18)),
            )
            .show(ui, |ui| {
                // Header
                ui.horizontal(|ui| {
                    if let Some(logo) = &self.logo {
                        ui.add(egui::Image::new((logo.id(), egui::vec2(36.0, 36.0))));
                        ui.add_space(4.0);
                    }
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.label(
                            egui::RichText::new("WithCrypt")
                                .size(22.0)
                                .strong()
                                .color(pal.text),
                        );
                        ui.label(
                            egui::RichText::new("파일은 그대로, 내용은 비공개로.")
                                .size(13.0)
                                .color(pal.muted),
                        );
                    });
                });
                ui.add_space(12.0);
                // Inputs are locked while a job runs.
                let busy = self.worker.is_some();
                ui.add_enabled_ui(!busy, |ui| {
                    let old = self.mode;
                    segmented(
                        ui,
                        &pal,
                        &mut self.mode,
                        &[
                            (Mode::Encrypt, "암호화"),
                            (Mode::Decrypt, "복호화"),
                            (Mode::Verify, "검증"),
                        ],
                    );
                    // Switching mode refreshes the header preview and clears old messages.
                    if old != self.mode {
                        self.preview_header();
                        self.message.clear();
                    }
                    ui.add_space(10.0);
                    card(&pal).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        field_label(ui, &pal, "입력 파일");
                        ui.horizontal(|ui| {
                            let browse_width = 92.0;
                            let width =
                                ui.available_width() - browse_width - ui.spacing().item_spacing.x;
                            if ui
                                .add(
                                    egui::TextEdit::singleline(&mut self.input)
                                        .desired_width(width)
                                        .min_size(egui::vec2(0.0, FIELD_HEIGHT))
                                        .margin(egui::Margin::symmetric(10, 8))
                                        .hint_text("파일을 선택하거나 경로를 입력하세요"),
                                )
                                .changed()
                            {
                                // Typed text replaces any previously picked path.
                                self.selected_input = None;
                                self.preview_header();
                            }
                            if ui
                                .add(
                                    egui::Button::new("찾아보기…")
                                        .min_size(egui::vec2(browse_width, FIELD_HEIGHT)),
                                )
                                .clicked()
                                && let Some(path) = rfd::FileDialog::new().pick_file()
                            {
                                self.input = path.to_string_lossy().into_owned();
                                self.selected_input = Some(path);
                                self.preview_header();
                            }
                        });
                        ui.add_space(8.0);
                        if self.mode == Mode::Encrypt {
                            field_label(ui, &pal, "암호화 알고리즘");
                            let width = ui.available_width();
                            ui.spacing_mut().interact_size.y = FIELD_HEIGHT;
                            egui::ComboBox::from_id_salt("suite")
                                .width(width)
                                .height(120.0)
                                .selected_text(self.suite.name())
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut self.suite,
                                        Suite::XChaCha20Poly1305,
                                        "XChaCha20-Poly1305 (기본)",
                                    );
                                    ui.selectable_value(
                                        &mut self.suite,
                                        Suite::Aes256Gcm,
                                        "AES-256-GCM",
                                    );
                                });
                        } else {
                            // Decrypt/verify: show the algorithm from the unauthenticated header.
                            field_label(ui, &pal, "파일 정보");
                            let (text, color) = if self.preview.is_empty() {
                                ("ESB 파일을 선택하면 헤더 정보가 표시됩니다", pal.muted)
                            } else if self.preview.starts_with("ESB") {
                                (self.preview.as_str(), pal.warning)
                            } else {
                                (self.preview.as_str(), pal.text)
                            };
                            egui::Frame::new()
                                .fill(pal.field)
                                .stroke(egui::Stroke::new(1.0, pal.border))
                                .corner_radius(RADIUS)
                                .inner_margin(egui::Margin::symmetric(10, 0))
                                .show(ui, |ui| {
                                    // Fixed height so this box lines up with the other input rows.
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(ui.available_width(), FIELD_HEIGHT - 2.0),
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            ui.set_min_size(ui.max_rect().size());
                                            ui.add(
                                                egui::Label::new(
                                                    egui::RichText::new(text).color(color),
                                                )
                                                .truncate(),
                                            );
                                        },
                                    );
                                });
                        }
                        ui.add_space(8.0);
                        field_label(ui, &pal, "비밀번호");
                        ui.horizontal(|ui| {
                            let toggle_width = 64.0;
                            let width =
                                ui.available_width() - toggle_width - ui.spacing().item_spacing.x;
                            password_edit(
                                ui,
                                &mut self.password,
                                self.show_password,
                                "password",
                                width,
                            );
                            if ui
                                .add(
                                    egui::Button::new(if self.show_password {
                                        "숨기기"
                                    } else {
                                        "표시"
                                    })
                                    .selected(self.show_password)
                                    .min_size(egui::vec2(toggle_width, FIELD_HEIGHT)),
                                )
                                .on_hover_text("비밀번호 표시")
                                .clicked()
                            {
                                self.show_password = !self.show_password;
                            }
                        });
                    });
                    ui.add_space(12.0);
                    let label = match self.mode {
                        Mode::Encrypt => "암호화 시작",
                        Mode::Decrypt => "복호화 시작",
                        Mode::Verify => "전체 검증 시작",
                    };
                    if ui
                        .add_sized(
                            [ui.available_width(), 40.0],
                            egui::Button::new(
                                egui::RichText::new(label)
                                    .size(15.0)
                                    .strong()
                                    .color(egui::Color32::WHITE),
                            )
                            .fill(pal.accent)
                            .stroke(egui::Stroke::NONE)
                            .corner_radius(RADIUS),
                        )
                        .clicked()
                    {
                        self.start(&ctx);
                    }
                });
                ui.add_space(10.0);
                // Status area: progress, last result, or a reminder about safety.
                if !self.status_ui(ui, &ctx, &pal) {
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new(
                                "원본 파일은 보존됩니다 · 기존 출력 파일은 덮어쓰지 않습니다",
                            )
                            .size(11.5)
                            .color(pal.muted),
                        );
                    });
                }
            });
    }
}
impl Desktop {
    /// Progress while working, otherwise the last result. False when empty.
    fn status_ui(&self, ui: &mut egui::Ui, ctx: &egui::Context, pal: &Palette) -> bool {
        if let Some(worker) = &self.worker {
            let cancelling = worker.cancel.load(Ordering::Relaxed);
            // Copy the latest progress so the lock is not held while drawing.
            let progress = worker.progress.lock().map(|p| *p).ok();
            status_frame(pal.accent).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.spinner();
                    if cancelling {
                        ui.label(egui::RichText::new(CANCELLING).color(pal.text));
                    } else if let Some(p) = progress {
                        let stage = match p.stage {
                            Stage::Kdf => "키 파생 중",
                            Stage::Processing => "파일 처리 중",
                            Stage::Verifying => "무결성 검증 중",
                            Stage::Committing => "결과 저장 중",
                            Stage::Complete => "완료",
                        };
                        ui.label(egui::RichText::new(stage).strong().color(pal.text));
                        ui.label(
                            egui::RichText::new(format!("{:.1} MiB", p.bytes as f64 / 1048576.0))
                                .color(pal.muted),
                        );
                    }
                    if !cancelling {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(egui::Button::new("취소").small()).clicked() {
                                worker.cancel.store(true, Ordering::Relaxed);
                            }
                        });
                    }
                });
                ui.add_space(4.0);
                let fraction = progress.and_then(|p| progress_fraction(p, worker.total));
                // Animate per job so a new job does not slide down from 100%.
                let id = egui::Id::new(("progress", Arc::as_ptr(&worker.progress) as usize));
                let shown = fraction.map(|f| ctx.animate_value_with_time(id, f, 0.2));
                ui.horizontal(|ui| {
                    let percent_width = 44.0;
                    let width = ui.available_width() - percent_width - ui.spacing().item_spacing.x;
                    progress_bar(ui, pal, width, shown);
                    let text = shown.map_or("—".to_owned(), |f| format!("{:.0}%", f * 100.0));
                    ui.add_sized(
                        [percent_width, 16.0],
                        egui::Label::new(
                            egui::RichText::new(text)
                                .size(12.5)
                                .strong()
                                .color(pal.text),
                        ),
                    );
                });
            });
            ctx.request_repaint_after(Duration::from_millis(100));
            true
        } else if !self.message.is_empty() {
            // Colour by outcome: green = success, accent = info or cancelled, red = error.
            let color = if self.message.starts_with("완료") {
                pal.success
            } else if self.prepared.is_some() || self.message.contains("취소") {
                pal.accent
            } else {
                pal.danger
            };
            status_frame(color).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(egui::RichText::new(&self.message).color(pal.text));
            });
            true
        } else {
            false
        }
    }
}
impl Desktop {
    /// Compact window for Explorer menu launches. The result is saved beside the input.
    fn shell_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, pal: &Palette) {
        let path = self.input_path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let folder = path
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let (title, result) = match self.mode {
            Mode::Encrypt => ("WithCrypt로 암호화", format!("{name}.esb")),
            _ => ("WithCrypt로 복호화", "저장된 원본 파일명".to_owned()),
        };
        // Inputs are locked while a job runs.
        let busy = self.worker.is_some();
        // After success the main button turns into "닫기" (close).
        let done = !busy && self.message.starts_with("완료");
        // Enter starts from anywhere; consume it so no focused button also fires.
        if !busy
            && !done
            && ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Enter))
        {
            self.start(ctx);
        }
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(pal.bg)
                    .inner_margin(egui::Margin::symmetric(24, 18)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if let Some(logo) = &self.logo {
                        ui.add(egui::Image::new((logo.id(), egui::vec2(28.0, 28.0))));
                    }
                    ui.label(
                        egui::RichText::new(title)
                            .size(18.0)
                            .strong()
                            .color(pal.text),
                    );
                });
                ui.add_space(12.0);
                card(pal).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    field_label(ui, pal, "대상 파일");
                    ui.add(
                        egui::Label::new(egui::RichText::new(&name).strong().color(pal.text))
                            .truncate(),
                    );
                    for (label, value) in
                        [("저장 위치", folder.as_str()), ("결과", result.as_str())]
                    {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!("{label} · {value}"))
                                    .size(12.5)
                                    .color(pal.muted),
                            )
                            .truncate(),
                        );
                    }
                    if self.mode != Mode::Encrypt && !self.preview.is_empty() {
                        let color = if self.preview.starts_with("ESB") {
                            pal.warning
                        } else {
                            pal.muted
                        };
                        ui.label(egui::RichText::new(&self.preview).size(12.5).color(color));
                    }
                    ui.add_space(8.0);
                    ui.add_enabled_ui(!busy && !done, |ui| {
                        if self.mode == Mode::Encrypt {
                            field_label(ui, pal, "암호화 알고리즘");
                            let width = ui.available_width();
                            ui.spacing_mut().interact_size.y = FIELD_HEIGHT;
                            egui::ComboBox::from_id_salt("suite")
                                .width(width)
                                .selected_text(self.suite.name())
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut self.suite,
                                        Suite::XChaCha20Poly1305,
                                        "XChaCha20-Poly1305 (기본)",
                                    );
                                    ui.selectable_value(
                                        &mut self.suite,
                                        Suite::Aes256Gcm,
                                        "AES-256-GCM",
                                    );
                                });
                            ui.add_space(8.0);
                        }
                        field_label(ui, pal, "비밀번호");
                        ui.horizontal(|ui| {
                            let toggle_width = 64.0;
                            let width =
                                ui.available_width() - toggle_width - ui.spacing().item_spacing.x;
                            let response = password_edit(
                                ui,
                                &mut self.password,
                                self.show_password,
                                "password",
                                width,
                            );
                            // Put the cursor in the password field so the user can type right away.
                            if !busy && !done && ui.memory(|m| m.focused().is_none()) {
                                response.request_focus();
                            }
                            if ui
                                .add(
                                    egui::Button::new(if self.show_password {
                                        "숨기기"
                                    } else {
                                        "표시"
                                    })
                                    .selected(self.show_password)
                                    .min_size(egui::vec2(toggle_width, FIELD_HEIGHT)),
                                )
                                .clicked()
                            {
                                self.show_password = !self.show_password;
                            }
                        });
                    });
                });
                ui.add_space(12.0);
                let label = match (done, self.mode) {
                    (true, _) => "닫기",
                    (false, Mode::Encrypt) => "암호화 시작",
                    (false, _) => "복호화 시작",
                };
                let clicked = ui
                    .add_enabled_ui(!busy, |ui| {
                        ui.add_sized(
                            [ui.available_width(), 40.0],
                            egui::Button::new(
                                egui::RichText::new(label)
                                    .size(15.0)
                                    .strong()
                                    .color(egui::Color32::WHITE),
                            )
                            .fill(pal.accent)
                            .stroke(egui::Stroke::NONE)
                            .corner_radius(RADIUS),
                        )
                        .clicked()
                    })
                    .inner;
                if clicked && done {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                } else if clicked {
                    self.start(ctx);
                }
                ui.add_space(10.0);
                self.status_ui(ui, ctx, pal);
            });
    }
}
/// Plaintext bytes behind an ESB of `len` bytes (format-v1): header 64, META
/// 29+2+name, FINAL 29+48, and 29 bytes (record header + tag) per DATA chunk.
/// The unknown name length makes it a slight overestimate. Only drives the bar.
fn estimated_plaintext(len: u64) -> u64 {
    let body = len.saturating_sub(64 + 29 + 2 + 29 + 48);
    let records = body.div_ceil(withcrypt_core::CHUNK_SIZE as u64 + 29);
    body.saturating_sub(records * 29)
}
/// Total plaintext bytes expected for the progress percentage.
fn expected_total(mode: Mode, input: &Path) -> u64 {
    let len = std::fs::metadata(input).map_or(0, |m| m.len());
    if mode == Mode::Encrypt {
        len
    } else {
        estimated_plaintext(len)
    }
}
/// None while the size is unknown (key derivation): the bar runs indeterminate.
fn progress_fraction(p: Progress, total: u64) -> Option<f32> {
    match p.stage {
        Stage::Kdf => None,
        Stage::Committing | Stage::Complete => Some(1.0),
        Stage::Processing | Stage::Verifying if total == 0 => Some(1.0),
        Stage::Processing | Stage::Verifying => {
            Some((p.bytes as f64 / total as f64).min(1.0) as f32)
        }
    }
}
/// Draws the progress bar: a determinate fill with a moving sheen, or an
/// indeterminate gliding segment when `fraction` is None.
fn progress_bar(ui: &mut egui::Ui, pal: &Palette, width: f32, fraction: Option<f32>) {
    let height = 8.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, height / 2.0, pal.track);
    let time = ui.input(|i| i.time) as f32;
    let fill = match fraction {
        Some(f) if f > 0.0 => {
            egui::Rect::from_min_size(rect.min, egui::vec2((rect.width() * f).max(height), height))
        }
        Some(_) => return,
        None => {
            // Indeterminate: a short segment gliding back and forth.
            let segment = rect.width() * 0.28;
            let t = (time * 1.6).sin() * 0.5 + 0.5;
            let left = rect.left() + (rect.width() - segment) * t;
            ui.ctx().request_repaint();
            egui::Rect::from_min_size(egui::pos2(left, rect.top()), egui::vec2(segment, height))
        }
    };
    gradient_pill(painter, fill, pal.accent, pal.accent_alt);
    if fraction.is_some_and(|f| f < 1.0) {
        // A soft sheen sweeping across the filled part while work continues.
        let band = 48.0;
        let x = fill.left() - band + (time * 90.0) % (fill.width() + band * 2.0);
        let clip = painter.with_clip_rect(fill.shrink2(egui::vec2(height / 2.0, 0.0)));
        let glow = egui::Color32::from_white_alpha(70);
        let clear = egui::Color32::TRANSPARENT;
        let mut mesh = egui::Mesh::default();
        for (dx, color) in [(0.0, clear), (band / 2.0, glow), (band, clear)] {
            mesh.colored_vertex(egui::pos2(x + dx, fill.top()), color);
            mesh.colored_vertex(egui::pos2(x + dx, fill.bottom()), color);
        }
        for i in [0, 2] {
            mesh.add_triangle(i, i + 1, i + 2);
            mesh.add_triangle(i + 2, i + 1, i + 3);
        }
        clip.add(mesh);
        ui.ctx().request_repaint();
    }
}
/// Horizontal gradient with round caps: anti-aliased caps plus a gradient body.
fn gradient_pill(
    painter: &egui::Painter,
    rect: egui::Rect,
    left: egui::Color32,
    right: egui::Color32,
) {
    let r = rect.height() / 2.0;
    if rect.width() <= rect.height() + 1.0 {
        painter.rect_filled(rect, r, left);
        return;
    }
    let (a, b) = (rect.left() + r, rect.right() - r);
    painter.circle_filled(egui::pos2(a, rect.center().y), r, left);
    painter.circle_filled(egui::pos2(b, rect.center().y), r, right);
    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(egui::pos2(a, rect.top()), left);
    mesh.colored_vertex(egui::pos2(a, rect.bottom()), left);
    mesh.colored_vertex(egui::pos2(b, rect.top()), right);
    mesh.colored_vertex(egui::pos2(b, rect.bottom()), right);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(2, 1, 3);
    painter.add(mesh);
}
/// Shown while a cancel waits for Argon2, which cannot stop midway.
const CANCELLING: &str = "안전하게 취소하는 중입니다. 키 파생이 끝날 때까지 잠시 기다려 주세요.";
/// Logo drawn inside the window.
const LOGO: &[u8] = include_bytes!("../../../resources/ProgramIcon.png");
/// Native window/taskbar icon. The PE file icon is embedded from the matching
/// ICO by build.rs because Windows Explorer does not use a PNG for executables.
#[cfg(target_os = "windows")]
const APP_ICON: &[u8] = include_bytes!("../../../resources/AppIcon2.png");
#[cfg(not(target_os = "windows"))]
const APP_ICON: &[u8] = LOGO;
/// Corner radius shared by inputs, buttons and boxes.
const RADIUS: u8 = 8;
/// Height of every single-line input row.
const FIELD_HEIGHT: f32 = 32.0;
#[derive(Clone, Copy)]
/// Colour tokens for one theme; `Palette::of` picks dark or light.
struct Palette {
    bg: egui::Color32,
    surface: egui::Color32,
    field: egui::Color32,
    border: egui::Color32,
    text: egui::Color32,
    muted: egui::Color32,
    accent: egui::Color32,
    accent_hover: egui::Color32,
    accent_alt: egui::Color32,
    track: egui::Color32,
    success: egui::Color32,
    warning: egui::Color32,
    danger: egui::Color32,
}
impl Palette {
    fn of(dark: bool) -> Self {
        use egui::Color32 as C;
        if dark {
            Self {
                bg: C::from_rgb(0x12, 0x14, 0x1a),
                surface: C::from_rgb(0x1b, 0x1e, 0x26),
                field: C::from_rgb(0x14, 0x16, 0x1d),
                border: C::from_rgb(0x2c, 0x31, 0x3c),
                text: C::from_rgb(0xe8, 0xea, 0xef),
                muted: C::from_rgb(0x8b, 0x92, 0xa1),
                accent: C::from_rgb(0x5b, 0x6c, 0xf9),
                accent_hover: C::from_rgb(0x72, 0x81, 0xfb),
                accent_alt: C::from_rgb(0x9b, 0x6c, 0xf6),
                track: C::from_rgb(0x2a, 0x2f, 0x3b),
                success: C::from_rgb(0x34, 0xc7, 0x7b),
                warning: C::from_rgb(0xf2, 0xb3, 0x4b),
                danger: C::from_rgb(0xf0, 0x5d, 0x5e),
            }
        } else {
            Self {
                bg: C::from_rgb(0xf4, 0xf5, 0xf8),
                surface: C::WHITE,
                field: C::from_rgb(0xf8, 0xf9, 0xfb),
                border: C::from_rgb(0xdd, 0xe1, 0xe8),
                text: C::from_rgb(0x1a, 0x1d, 0x24),
                muted: C::from_rgb(0x6b, 0x72, 0x80),
                accent: C::from_rgb(0x4f, 0x5b, 0xe8),
                accent_hover: C::from_rgb(0x43, 0x4e, 0xd6),
                accent_alt: C::from_rgb(0x85, 0x4d, 0xe8),
                track: C::from_rgb(0xe3, 0xe6, 0xee),
                success: C::from_rgb(0x1f, 0x9d, 0x5c),
                warning: C::from_rgb(0xc2, 0x7c, 0x0e),
                danger: C::from_rgb(0xd9, 0x3a, 0x3b),
            }
        }
    }
}
/// Rounded panel that groups the form fields.
fn card(pal: &Palette) -> egui::Frame {
    egui::Frame::new()
        .fill(pal.surface)
        .stroke(egui::Stroke::new(1.0, pal.border))
        .corner_radius(12)
        .inner_margin(egui::Margin::same(14))
}
/// Tinted box for status messages, in the given colour.
fn status_frame(color: egui::Color32) -> egui::Frame {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.5)))
        .corner_radius(RADIUS)
        .inner_margin(egui::Margin::symmetric(12, 8))
        .outer_margin(egui::Margin::ZERO)
}
/// Small muted caption above an input.
fn field_label(ui: &mut egui::Ui, pal: &Palette, text: &str) {
    ui.label(
        egui::RichText::new(text)
            .size(12.5)
            .strong()
            .color(pal.muted),
    );
    ui.add_space(2.0);
}
/// Segmented control: a row of pill buttons, one per mode.
fn segmented(ui: &mut egui::Ui, pal: &Palette, value: &mut Mode, options: &[(Mode, &str)]) {
    egui::Frame::new()
        .fill(pal.field)
        .stroke(egui::Stroke::new(1.0, pal.border))
        .corner_radius(10)
        .inner_margin(egui::Margin::same(3))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            let gaps = ui.spacing().item_spacing.x * (options.len() - 1) as f32;
            let width = (ui.available_width() - gaps) / options.len() as f32;
            ui.horizontal(|ui| {
                for &(mode, text) in options {
                    let selected = *value == mode;
                    let label = egui::RichText::new(text).size(14.0);
                    let button = if selected {
                        egui::Button::new(label.strong().color(egui::Color32::WHITE))
                            .fill(pal.accent)
                    } else {
                        egui::Button::new(label.color(pal.muted)).frame_when_inactive(false)
                    };
                    if ui
                        .add(
                            button
                                .stroke(egui::Stroke::NONE)
                                .corner_radius(RADIUS - 1)
                                .min_size(egui::vec2(width, 30.0)),
                        )
                        .clicked()
                    {
                        *value = mode;
                    }
                }
            });
        });
}
/// Password field; masked unless `show` is set.
fn password_edit(
    ui: &mut egui::Ui,
    text: &mut String,
    show: bool,
    id: &str,
    width: f32,
) -> egui::Response {
    let mut output = egui::TextEdit::singleline(text)
        .password(!show)
        .id_salt(id)
        .desired_width(width)
        .min_size(egui::vec2(0.0, FIELD_HEIGHT))
        .margin(egui::Margin::symmetric(10, 8))
        .hint_text("비밀번호")
        .show(ui);
    // Do not retain plaintext password history in the framework's undo buffer.
    output.state.clear_undoer();
    output.state.store(ui.ctx(), output.response.id);
    output.response.response
}
/// Applies text sizes, spacing and the colours of `pal` to an egui style.
fn apply_style(style: &mut egui::Style, pal: &Palette) {
    use egui::{FontFamily::Proportional, FontId, Stroke, TextStyle};
    style.text_styles = [
        (TextStyle::Heading, FontId::new(22.0, Proportional)),
        (TextStyle::Body, FontId::new(14.0, Proportional)),
        (TextStyle::Button, FontId::new(14.0, Proportional)),
        (TextStyle::Small, FontId::new(11.5, Proportional)),
        (
            TextStyle::Monospace,
            FontId::new(13.0, egui::FontFamily::Monospace),
        ),
    ]
    .into();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.interact_size.y = 30.0;
    let v = &mut style.visuals;
    v.panel_fill = pal.bg;
    v.window_fill = pal.surface;
    v.window_stroke = Stroke::new(1.0, pal.border);
    v.window_corner_radius = 10.into();
    v.menu_corner_radius = RADIUS.into();
    v.extreme_bg_color = pal.field;
    v.text_edit_bg_color = Some(pal.field);
    v.faint_bg_color = pal.surface;
    v.override_text_color = None;
    v.hyperlink_color = pal.accent;
    v.selection.bg_fill = pal.accent.gamma_multiply(0.35);
    v.selection.stroke = Stroke::new(1.5, pal.accent);
    v.warn_fg_color = pal.warning;
    v.error_fg_color = pal.danger;
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = pal.surface;
    w.noninteractive.weak_bg_fill = pal.surface;
    w.noninteractive.bg_stroke = Stroke::new(1.0, pal.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, pal.text);
    w.inactive.bg_fill = pal.field;
    w.inactive.weak_bg_fill = pal.field;
    w.inactive.bg_stroke = Stroke::new(1.0, pal.border);
    w.inactive.fg_stroke = Stroke::new(1.0, pal.text);
    w.hovered.bg_fill = pal.field;
    w.hovered.weak_bg_fill = pal.border.gamma_multiply(0.6);
    w.hovered.bg_stroke = Stroke::new(1.0, pal.accent_hover.gamma_multiply(0.7));
    w.hovered.fg_stroke = Stroke::new(1.5, pal.text);
    w.active.bg_fill = pal.field;
    w.active.weak_bg_fill = pal.border;
    w.active.bg_stroke = Stroke::new(1.0, pal.accent);
    w.active.fg_stroke = Stroke::new(1.5, pal.text);
    w.open.bg_fill = pal.field;
    w.open.weak_bg_fill = pal.field;
    w.open.bg_stroke = Stroke::new(1.0, pal.accent);
    w.open.fg_stroke = Stroke::new(1.0, pal.text);
    for visuals in [
        &mut w.noninteractive,
        &mut w.inactive,
        &mut w.hovered,
        &mut w.active,
        &mut w.open,
    ] {
        visuals.corner_radius = RADIUS.into();
        visuals.expansion = 0.0;
    }
}
/// One-time setup: load a system Korean font and register both themes.
fn configure(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    // egui's bundled fonts have no Hangul glyphs; use the first system font found.
    let paths = [
        "/System/Library/Fonts/AppleSDGothicNeo.ttc",
        "C:\\Windows\\Fonts\\malgun.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
    ];
    for path in paths {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("korean".into(), egui::FontData::from_owned(bytes).into());
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "korean".into());
            break;
        }
    }
    ctx.set_fonts(fonts);
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        let pal = Palette::of(theme == egui::Theme::Dark);
        ctx.style_mut_of(theme, |style| apply_style(style, &pal));
    }
}
/// Shown when the command line is not understood.
const USAGE: &str = "사용법: withcrypt-gui [--encrypt 파일 | --decrypt 파일]\n탐색기 메뉴 등록·해제는 withcrypt-setup을 사용하세요.";
/// How the app was started.
enum Launch {
    Window,
    Shell(Mode, PathBuf),
}
/// No arguments opens the main window; `--encrypt` or `--decrypt <file>` the compact one.
fn parse_launch(args: &[std::ffi::OsString]) -> Option<Launch> {
    match args {
        [] => Some(Launch::Window),
        [flag, path] if flag.as_os_str() == "--encrypt" => {
            Some(Launch::Shell(Mode::Encrypt, path.into()))
        }
        [flag, path] if flag.as_os_str() == "--decrypt" => {
            Some(Launch::Shell(Mode::Decrypt, path.into()))
        }
        _ => None,
    }
}
fn main() {
    match std::panic::catch_unwind(run) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => show_startup_error(&error.to_string()),
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("알 수 없는 내부 오류");
            show_startup_error(message);
            std::process::exit(101);
        }
    }
}

fn show_startup_error(error: &str) {
    rfd::MessageDialog::new()
        .set_title("WithCrypt 시작 오류")
        .set_description(format!("프로그램을 시작할 수 없습니다.\n\n{error}"))
        .set_level(rfd::MessageLevel::Error)
        .show();
}

/// Picks the window from the command line and runs the egui event loop.
fn run() -> eframe::Result {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (app, size) = match parse_launch(&args) {
        Some(Launch::Window) => (Desktop::default(), [600.0, 548.0]),
        Some(Launch::Shell(mode, path)) => (Desktop::for_shell(mode, path), [480.0, 512.0]),
        None => {
            rfd::MessageDialog::new()
                .set_title("WithCrypt")
                .set_description(USAGE)
                .set_level(rfd::MessageLevel::Error)
                .show();
            return Ok(());
        }
    };
    let icon = eframe::icon_data::from_png_bytes(APP_ICON)
        .map_err(|error| eframe::Error::AppCreation(Box::new(error)))?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_icon(icon)
            .with_resizable(false)
            .with_inner_size(size)
            .with_maximize_button(false),
        renderer: renderer(),
        ..Default::default()
    };
    #[cfg(windows)]
    let options = eframe::NativeOptions {
        wgpu_options: windows_wgpu_configuration(),
        ..options
    };
    eframe::run_native(
        "WithCrypt",
        options,
        Box::new(|cc| {
            configure(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    )
}

/// Windows draws through Direct3D 12 so VMs do not require an OpenGL driver.
fn renderer() -> eframe::Renderer {
    #[cfg(windows)]
    return eframe::Renderer::Wgpu;
    #[cfg(not(windows))]
    eframe::Renderer::Glow
}

/// Prefers a hardware DX12 adapter and falls back to Microsoft's WARP
/// software renderer when a VM has no usable virtual GPU driver.
#[cfg(windows)]
fn windows_wgpu_configuration() -> eframe::egui_wgpu::WgpuConfiguration {
    use eframe::egui_wgpu::{WgpuConfiguration, WgpuSetup};
    use eframe::wgpu::{Backends, DeviceType};
    use std::sync::Arc;

    let mut configuration = WgpuConfiguration::default();
    let WgpuSetup::CreateNew(setup) = &mut configuration.wgpu_setup else {
        unreachable!("the default wgpu setup creates a new adapter");
    };
    setup.instance_descriptor.backends = Backends::DX12;
    setup.native_adapter_selector = Some(Arc::new(|adapters, surface| {
        let compatible = |adapter: &&eframe::wgpu::Adapter| {
            surface.is_none_or(|surface| adapter.is_surface_supported(surface))
        };
        adapters
            .iter()
            .filter(compatible)
            .min_by_key(|adapter| adapter.get_info().device_type == DeviceType::Cpu)
            .cloned()
            .ok_or_else(|| "사용 가능한 Direct3D 12 또는 WARP 어댑터가 없습니다".to_owned())
    }));
    configuration
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Polls until the background job finishes (30 s limit).
    fn wait(app: &mut Desktop) {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while app.worker.is_some() {
            app.poll();
            assert!(std::time::Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
    }
    #[test]
    fn progress_estimate_tracks_plaintext() {
        let ctx = egui::Context::default();
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("big.bin");
        let size = withcrypt_core::CHUNK_SIZE * 2 + 12345;
        std::fs::write(&input, vec![7u8; size]).unwrap();
        assert_eq!(expected_total(Mode::Encrypt, &input), size as u64);
        let mut app = Desktop::default();
        app.input = input.to_string_lossy().into_owned();
        app.password = Zeroizing::new("pw".into());
        app.start_with_chooser(&ctx, &mut |input, name, _| Some(input.with_file_name(name)));
        wait(&mut app);
        let estimate = expected_total(Mode::Decrypt, &dir.path().join("big.bin.esb"));
        // Off only by the stored filename length ("big.bin").
        assert_eq!(estimate, size as u64 + "big.bin".len() as u64);
        let at = |stage, bytes| progress_fraction(Progress { stage, bytes }, 200);
        assert_eq!(at(Stage::Kdf, 0), None);
        assert_eq!(at(Stage::Processing, 50), Some(0.25));
        assert_eq!(at(Stage::Verifying, 999), Some(1.0));
        assert_eq!(at(Stage::Committing, 0), Some(1.0));
        assert_eq!(estimated_plaintext(0), 0);
    }
    #[test]
    fn launch_arguments() {
        let args = |v: &[&str]| {
            v.iter()
                .map(Into::into)
                .collect::<Vec<std::ffi::OsString>>()
        };
        assert!(matches!(parse_launch(&args(&[])), Some(Launch::Window)));
        assert!(matches!(
            parse_launch(&args(&["--encrypt", "a b.txt"])),
            Some(Launch::Shell(Mode::Encrypt, p)) if p == Path::new("a b.txt")
        ));
        assert!(matches!(
            parse_launch(&args(&["--decrypt", "a.esb"])),
            Some(Launch::Shell(Mode::Decrypt, _))
        ));
        assert!(parse_launch(&args(&["--register-shell"])).is_none());
        assert!(parse_launch(&args(&["--encrypt"])).is_none());
        assert!(parse_launch(&args(&["--verify", "a.esb"])).is_none());
    }
    #[test]
    fn shell_mode_saves_beside_input_without_dialog() {
        let ctx = egui::Context::default();
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("보고서 v2.pdf");
        std::fs::write(&input, b"shell data").unwrap();
        let mut app = Desktop::for_shell(Mode::Encrypt, input.clone());
        app.password = Zeroizing::new("pw".into());
        app.start(&ctx);
        wait(&mut app);
        assert!(app.message.starts_with("완료"), "{}", app.message);
        let encrypted = dir.path().join("보고서 v2.pdf.esb");
        assert!(encrypted.exists());
        // An existing result is never overwritten.
        app.password = Zeroizing::new("pw".into());
        app.start(&ctx);
        wait(&mut app);
        assert!(app.message.contains("이미 존재"), "{}", app.message);

        std::fs::rename(&input, dir.path().join("moved.pdf")).unwrap();
        let mut app = Desktop::for_shell(Mode::Decrypt, encrypted);
        assert!(!app.preview.is_empty());
        app.password = Zeroizing::new("pw".into());
        app.start(&ctx);
        wait(&mut app);
        assert!(app.prepared.is_some());
        let mut choose = app.chooser();
        app.save_prepared(&ctx, &mut choose);
        wait(&mut app);
        assert!(app.message.starts_with("완료"), "{}", app.message);
        assert_eq!(std::fs::read(&input).unwrap(), b"shell data");
    }
    #[test]
    fn background_worker_both_suites() {
        let ctx = egui::Context::default();
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("한글 파일.tar.gz");
        let bytes: Vec<u8> = (0..8193).map(|n| n as u8).collect();
        std::fs::write(&input, &bytes).unwrap();
        for suite in [Suite::XChaCha20Poly1305, Suite::Aes256Gcm] {
            let enc = dir.path().join(format!("{}.esb", suite.id()));
            let out = dir.path().join(format!("renamed-{}.bin", suite.id()));
            let mut app = Desktop::default();
            app.suite = suite;
            app.input = input.to_string_lossy().into_owned();
            app.password = Zeroizing::new("한글 pw".into());
            app.confirmation = Zeroizing::new("한글 pw".into());
            app.start_with_chooser(&ctx, &mut |_, name, encrypted| {
                assert_eq!(name, "한글 파일.tar.gz.esb");
                assert!(encrypted);
                Some(enc.clone())
            });
            assert!(app.worker.is_some());
            assert!(app.password.is_empty());
            assert!(app.confirmation.is_empty());
            wait(&mut app);
            assert!(app.message.starts_with("완료"), "{}", app.message);
            app.mode = Mode::Verify;
            app.input = enc.to_string_lossy().into_owned();
            app.preview_header();
            assert!(app.preview.contains(suite.name()));
            app.password = Zeroizing::new("한글 pw".into());
            app.start_with_chooser(&ctx, &mut |_, _, _| panic!("verify dialog"));
            wait(&mut app);
            assert!(app.message.starts_with("완료"));
            app.mode = Mode::Decrypt;
            app.password = Zeroizing::new("한글 pw".into());
            app.start_with_chooser(&ctx, &mut |_, _, _| panic!("unauthenticated dialog"));
            wait(&mut app);
            assert!(app.prepared.is_some());
            assert!(!out.exists());
            app.save_prepared(&ctx, &mut |_, name, encrypted| {
                assert_eq!(name, "한글 파일.tar.gz");
                assert!(!encrypted);
                Some(out.clone())
            });
            wait(&mut app);
            assert!(app.message.starts_with("완료"));
            assert_eq!(std::fs::read(&out).unwrap(), bytes);
            // Wrong password never presents a filename or save dialog.
            app.password = Zeroizing::new("wrong".into());
            app.start_with_chooser(&ctx, &mut |_, _, _| panic!("unexpected dialog"));
            wait(&mut app);
            assert!(app.prepared.is_none());
            assert!(app.message.contains("손상"));
            // Cancelling the save dialog drops prepared keys without writing anything.
            app.password = Zeroizing::new("한글 pw".into());
            app.start_with_chooser(&ctx, &mut |_, _, _| panic!("unexpected dialog"));
            wait(&mut app);
            app.save_prepared(&ctx, &mut |_, _, _| None);
            assert!(app.worker.is_none());
            assert!(app.prepared.is_none());
            assert!(app.message.contains("취소"));
        }
    }
}
