#![forbid(unsafe_code)]
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
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

#[derive(Default, PartialEq, Clone, Copy)]
enum Mode {
    #[default]
    Encrypt,
    Decrypt,
    Verify,
}
enum WorkerResult {
    Prepared(Box<files::PreparedDecryption>),
    Complete(Summary),
}
struct Worker {
    cancel: Arc<AtomicBool>,
    progress: Arc<Mutex<Progress>>,
    result: mpsc::Receiver<withcrypt_core::Result<WorkerResult>>,
    handle: thread::JoinHandle<()>,
}
#[derive(Default)]
struct Desktop {
    mode: Mode,
    suite: Suite,
    input: String,
    selected_input: Option<PathBuf>,
    password: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    show_password: bool,
    preview: String,
    message: String,
    worker: Option<Worker>,
    prepared: Option<Box<files::PreparedDecryption>>,
    closing: bool,
    logo: Option<egui::TextureHandle>,
}
impl Desktop {
    fn input_path(&self) -> PathBuf {
        self.selected_input
            .clone()
            .unwrap_or_else(|| self.input.clone().into())
    }
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
    fn start(&mut self, ctx: &egui::Context) {
        self.start_with_chooser(ctx, &mut Self::choose_save);
    }
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
        let password = std::mem::take(&mut self.password);
        self.confirmation.zeroize();
        self.show_password = false;
        self.spawn_work(ctx, move |observer| match mode {
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
    fn cancel_selection(&mut self) {
        self.password.zeroize();
        self.confirmation.zeroize();
        self.show_password = false;
        self.message = "저장을 취소했습니다. 출력 파일을 만들지 않았습니다.".into();
    }
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
        self.spawn_work(ctx, move |observer| {
            prepared.save(&output, observer).map(WorkerResult::Complete)
        });
    }
    fn spawn_work(
        &mut self,
        ctx: &egui::Context,
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
            result: rx,
            handle,
        });
        self.message.clear();
    }
    fn poll(&mut self) {
        let result = self
            .worker
            .as_ref()
            .and_then(|w| match w.result.try_recv() {
                Ok(r) => Some(r),
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
impl Drop for Desktop {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.cancel.store(true, Ordering::Relaxed);
            let _ = worker.handle.join();
        }
    }
}
impl eframe::App for Desktop {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        let ctx = ui.ctx().clone();
        if ctx.input(|i| i.viewport().close_requested())
            && (self.worker.is_some() || self.prepared.is_some())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.closing = true;
            if let Some(w) = &self.worker {
                w.cancel.store(true, Ordering::Relaxed);
            }
        }
        self.save_prepared(&ctx, &mut Self::choose_save);
        if self.closing && self.worker.is_none() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        let pal = Palette::of(ui.visuals().dark_mode);
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
                            password_edit(ui, &mut self.password, self.show_password, "password", width);
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
                if let Some(worker) = &self.worker {
                    let cancelling = worker.cancel.load(Ordering::Relaxed);
                    status_frame(pal.accent).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.spinner();
                            if cancelling {
                                ui.label(
                                    egui::RichText::new(
                                        "안전하게 취소하는 중입니다. 키 파생이 끝날 때까지 잠시 기다려 주세요.",
                                    )
                                    .color(pal.text),
                                );
                            } else if let Ok(p) = worker.progress.lock() {
                                let stage = match p.stage {
                                    Stage::Kdf => "키 파생 중",
                                    Stage::Processing => "파일 처리 중",
                                    Stage::Verifying => "무결성 검증 중",
                                    Stage::Committing => "결과 저장 중",
                                    Stage::Complete => "완료",
                                };
                                ui.label(egui::RichText::new(stage).strong().color(pal.text));
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{:.1} MiB",
                                        p.bytes as f64 / 1048576.0
                                    ))
                                    .color(pal.muted),
                                );
                            }
                            if !cancelling {
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button("취소").clicked() {
                                        worker.cancel.store(true, Ordering::Relaxed);
                                    }
                                });
                            }
                        });
                    });
                    ctx.request_repaint_after(Duration::from_millis(100));
                } else if !self.message.is_empty() {
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
                } else {
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
const LOGO: &[u8] = include_bytes!("../../../resources/ProgramIcon.png");
const RADIUS: u8 = 8;
const FIELD_HEIGHT: f32 = 32.0;
#[derive(Clone, Copy)]
struct Palette {
    bg: egui::Color32,
    surface: egui::Color32,
    field: egui::Color32,
    border: egui::Color32,
    text: egui::Color32,
    muted: egui::Color32,
    accent: egui::Color32,
    accent_hover: egui::Color32,
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
                success: C::from_rgb(0x1f, 0x9d, 0x5c),
                warning: C::from_rgb(0xc2, 0x7c, 0x0e),
                danger: C::from_rgb(0xd9, 0x3a, 0x3b),
            }
        }
    }
}
fn card(pal: &Palette) -> egui::Frame {
    egui::Frame::new()
        .fill(pal.surface)
        .stroke(egui::Stroke::new(1.0, pal.border))
        .corner_radius(12)
        .inner_margin(egui::Margin::same(14))
}
fn status_frame(color: egui::Color32) -> egui::Frame {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.5)))
        .corner_radius(RADIUS)
        .inner_margin(egui::Margin::symmetric(12, 8))
        .outer_margin(egui::Margin::ZERO)
}
fn field_label(ui: &mut egui::Ui, pal: &Palette, text: &str) {
    ui.label(
        egui::RichText::new(text)
            .size(12.5)
            .strong()
            .color(pal.muted),
    );
    ui.add_space(2.0);
}
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
fn password_edit(ui: &mut egui::Ui, text: &mut String, show: bool, id: &str, width: f32) {
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
}
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
fn configure(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
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
fn main() -> eframe::Result {
    let icon = eframe::icon_data::from_png_bytes(LOGO)
        .map_err(|error| eframe::Error::AppCreation(Box::new(error)))?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_icon(icon)
            .with_resizable(false)
            .with_inner_size([600.0, 500.0])
            .with_maximize_button(false),
        ..Default::default()
    };
    eframe::run_native(
        "WithCrypt",
        options,
        Box::new(|cc| {
            configure(&cc.egui_ctx);
            Ok(Box::new(Desktop::default()))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wait(app: &mut Desktop) {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while app.worker.is_some() {
            app.poll();
            assert!(std::time::Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
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
