#![forbid(unsafe_code)]
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use eframe::egui;
use std::{
    io::Read,
    path::PathBuf,
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
struct Worker {
    cancel: Arc<AtomicBool>,
    progress: Arc<Mutex<Progress>>,
    result: mpsc::Receiver<withcrypt_core::Result<Summary>>,
    handle: thread::JoinHandle<()>,
}
#[derive(Default)]
struct Desktop {
    mode: Mode,
    suite: Suite,
    input: String,
    output: String,
    selected_input: Option<PathBuf>,
    selected_output: Option<PathBuf>,
    password: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    show_password: bool,
    preview: String,
    message: String,
    worker: Option<Worker>,
    closing: bool,
}
impl Desktop {
    fn input_path(&self) -> PathBuf {
        self.selected_input
            .clone()
            .unwrap_or_else(|| self.input.clone().into())
    }
    fn output_path(&self) -> PathBuf {
        self.selected_output
            .clone()
            .unwrap_or_else(|| self.output.clone().into())
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
    fn start(&mut self, ctx: &egui::Context) {
        if self.worker.is_some() {
            return;
        }
        if self.input.is_empty() || self.mode != Mode::Verify && self.output.is_empty() {
            self.message = "입력 파일과 출력 경로를 지정하세요.".into();
            return;
        }
        if self.password.is_empty() {
            self.message = "비밀번호를 입력하세요.".into();
            return;
        }
        if self.mode == Mode::Encrypt && self.password != self.confirmation {
            self.message = "비밀번호 확인이 일치하지 않습니다.".into();
            return;
        }
        let input = self.input_path();
        let output = self.output_path();
        let operation = match self.mode {
            Mode::Encrypt => Operation::Encrypt(self.suite),
            Mode::Decrypt => Operation::Decrypt,
            Mode::Verify => Operation::Verify,
        };
        let password = std::mem::take(&mut self.password);
        self.confirmation.zeroize();
        self.show_password = false;
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
            let result = files::run(
                &input,
                Some(&output),
                password.as_bytes(),
                operation,
                &mut |p| {
                    if let Ok(mut value) = shared.lock() {
                        *value = p;
                    }
                    context.request_repaint();
                    !flag.load(Ordering::Relaxed)
                },
            );
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
            if let Some(worker) = self.worker.take() {
                let _ = worker.handle.join();
            }
            self.message = match result {
                Ok(s) => format!(
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
        if ctx.input(|i| i.viewport().close_requested()) && self.worker.is_some() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.closing = true;
            if let Some(w) = &self.worker {
                w.cancel.store(true, Ordering::Relaxed);
            }
        }
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
                if self.mode != Mode::Verify {
                    ui.add_space(10.0);
                    ui.label("출력 경로 · 새 파일로 저장");
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::TextEdit::singleline(&mut self.output).desired_width(450.0))
                            .changed()
                        {
                            self.selected_output = None;
                        }
                        if ui.button("저장 위치…").clicked() {
                            let mut dialog = rfd::FileDialog::new();
                            if self.mode == Mode::Encrypt {
                                dialog = dialog
                                    .add_filter("ESB", &["esb"])
                                    .set_file_name("encrypted.esb");
                            }
                            if let Some(path) = dialog.save_file() {
                                self.output = path.to_string_lossy().into_owned();
                                self.selected_output = Some(path);
                            }
                        }
                    });
                }
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
                if self.mode == Mode::Encrypt {
                    ui.label("비밀번호 확인");
                    password_edit(
                        ui,
                        &mut self.confirmation,
                        self.show_password,
                        "confirmation",
                    );
                }
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
    eframe::run_native(
        "WithCrypt",
        eframe::NativeOptions::default(),
        Box::new(|cc| {
            configure(&cc.egui_ctx);
            Ok(Box::new(Desktop::default()))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_password_validation() {
        let mut app = Desktop::default();
        assert_eq!(app.suite, Suite::XChaCha20Poly1305);
        app.start(&egui::Context::default());
        assert!(app.worker.is_none());
        app.input = "in".into();
        app.output = "out".into();
        app.password = Zeroizing::new("pw".into());
        app.confirmation = Zeroizing::new("wrong".into());
        app.start(&egui::Context::default());
        assert!(app.worker.is_none());
        assert!(app.message.contains("일치"));
    }

    #[test]
    fn background_worker_both_suites() {
        let ctx = egui::Context::default();
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("한글 파일.bin");
        let bytes: Vec<u8> = (0..8193).map(|n| n as u8).collect();
        std::fs::write(&input, &bytes).unwrap();
        for suite in [Suite::XChaCha20Poly1305, Suite::Aes256Gcm] {
            let enc = dir.path().join(format!("{}.esb", suite.id()));
            let out = dir.path().join(format!("{}.bin", suite.id()));
            let mut app = Desktop::default();
            app.suite = suite;
            app.input = input.to_string_lossy().into_owned();
            app.output = enc.to_string_lossy().into_owned();
            app.password = Zeroizing::new("한글 pw".into());
            app.confirmation = Zeroizing::new("한글 pw".into());
            app.start(&ctx);
            assert!(app.worker.is_some());
            assert!(app.password.is_empty());
            assert!(app.confirmation.is_empty());
            let finish = |app: &mut Desktop| {
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                while app.worker.is_some() {
                    app.poll();
                    assert!(std::time::Instant::now() < deadline);
                    thread::sleep(Duration::from_millis(5));
                }
                assert!(app.message.starts_with("완료"), "{}", app.message);
            };
            finish(&mut app);
            app.mode = Mode::Verify;
            app.input = enc.to_string_lossy().into_owned();
            app.preview_header();
            assert!(app.preview.contains(suite.name()));
            assert!(app.preview.contains("아직 인증되지"));
            app.password = Zeroizing::new("한글 pw".into());
            app.start(&ctx);
            finish(&mut app);
            app.mode = Mode::Decrypt;
            app.output = out.to_string_lossy().into_owned();
            app.password = Zeroizing::new("한글 pw".into());
            app.start(&ctx);
            finish(&mut app);
            assert_eq!(std::fs::read(out).unwrap(), bytes);
        }
    }
}
