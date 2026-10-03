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
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(16.0);
            ui.heading(egui::RichText::new("WithCrypt").size(32.0));
            ui.label("파일은 그대로, 내용은 비공개로.");
            ui.add_space(20.0);
            let busy = self.worker.is_some();
            ui.add_enabled_ui(!busy, |ui| {
                ui.horizontal(|ui| {
                    let old = self.mode;
                    ui.selectable_value(&mut self.mode, Mode::Encrypt, "암호화");
                    ui.selectable_value(&mut self.mode, Mode::Decrypt, "복호화");
                    ui.selectable_value(&mut self.mode, Mode::Verify, "검증");
                    if old != self.mode {
                        self.preview_header();
                        self.message.clear();
                    }
                });
                ui.add_space(16.0);
                ui.label("입력 파일");
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut self.input)
                                .desired_width(450.0)
                                .hint_text("파일을 선택하세요"),
                        )
                        .changed()
                    {
                        self.selected_input = None;
                        self.preview_header();
                    }
                    if ui.button("찾아보기…").clicked()
                        && let Some(path) = rfd::FileDialog::new().pick_file()
                    {
                        self.input = path.to_string_lossy().into_owned();
                        self.selected_input = Some(path);
                        self.preview_header();
                    }
                });
                ui.add_space(12.0);
                if self.mode == Mode::Encrypt {
                    ui.label("암호화 알고리즘");
                    egui::ComboBox::from_id_salt("suite")
                        .selected_text(self.suite.name())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.suite,
                                Suite::XChaCha20Poly1305,
                                "XChaCha20-Poly1305 (기본)",
                            );
                            ui.selectable_value(&mut self.suite, Suite::Aes256Gcm, "AES-256-GCM");
                        });
                } else {
                    ui.label(&self.preview);
                }
                ui.add_space(12.0);
                ui.label("비밀번호");
                password_edit(ui, &mut self.password, self.show_password, "password");
                ui.checkbox(&mut self.show_password, "비밀번호 표시");
                ui.add_space(12.0);
                if ui
                    .add_sized(
                        [160.0, 38.0],
                        egui::Button::new(match self.mode {
                            Mode::Encrypt => "암호화 시작",
                            Mode::Decrypt => "복호화 시작",
                            Mode::Verify => "전체 검증 시작",
                        }),
                    )
                    .clicked()
                {
                    self.start(&ctx);
                }
            });
            ui.add_space(16.0);
            if let Some(worker) = &self.worker {
                if let Ok(p) = worker.progress.lock() {
                    let stage = match p.stage {
                        Stage::Kdf => "키 파생 중",
                        Stage::Processing => "파일 처리 중",
                        Stage::Verifying => "무결성 검증 중",
                        Stage::Committing => "결과 저장 중",
                        Stage::Complete => "완료",
                    };
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(format!("{stage} · {:.1} MiB", p.bytes as f64 / 1048576.0));
                    });
                }
                if ui.button("취소").clicked() {
                    worker.cancel.store(true, Ordering::Relaxed);
                }
                if worker.cancel.load(Ordering::Relaxed) {
                    ui.label(
                        "안전하게 취소하는 중입니다. 키 파생이 끝날 때까지 잠시 기다려 주세요.",
                    );
                }
                ctx.request_repaint_after(Duration::from_millis(100));
            }
            if !self.message.is_empty() {
                ui.separator();
                ui.label(&self.message);
            }
            ui.add_space(16.0);
            ui.label(
                egui::RichText::new("원본 파일은 보존됩니다. 기존 출력 파일은 덮어쓰지 않습니다.")
                    .small(),
            );
        });
    }
}
fn password_edit(ui: &mut egui::Ui, text: &mut String, show: bool, id: &str) {
    let mut output = egui::TextEdit::singleline(text)
        .password(!show)
        .id_salt(id)
        .desired_width(450.0)
        .show(ui);
    // Do not retain plaintext password history in the framework's undo buffer.
    output.state.clear_undoer();
    output.state.store(ui.ctx(), output.response.id);
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
}
fn main() -> eframe::Result {
    let icon =
        eframe::icon_data::from_png_bytes(include_bytes!("../../../resources/ProgramIcon.png"))
            .map_err(|error| eframe::Error::AppCreation(Box::new(error)))?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_icon(icon)
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
