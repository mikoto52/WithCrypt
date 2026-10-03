#![forbid(unsafe_code)]
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    io::{self, IsTerminal},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use withcrypt_core::{
    Error, Stage, Suite,
    files::{self, Operation},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "withcrypt",
    version,
    about = "WithCrypt — 스트리밍 파일 암호화"
)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Encrypt {
        input: PathBuf,
        #[arg(long, value_name = "FILE", help = "출력 파일 (생략: 입력파일명.esb)")]
        output: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "xchacha20-poly1305")]
        algorithm: Algorithm,
    },
    Decrypt {
        input: PathBuf,
        #[arg(
            long,
            value_name = "DIRECTORY",
            help = "원본 파일명으로 복원할 기존 디렉터리"
        )]
        output: PathBuf,
    },
    Verify {
        input: PathBuf,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum Algorithm {
    #[value(name = "xchacha20-poly1305")]
    Xchacha20Poly1305,
    #[value(name = "aes-256-gcm")]
    Aes256Gcm,
}
impl From<Algorithm> for Suite {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::Xchacha20Poly1305 => Self::XChaCha20Poly1305,
            Algorithm::Aes256Gcm => Self::Aes256Gcm,
        }
    }
}
fn prompt_secret(prompt: &str) -> Result<Zeroizing<String>, Error> {
    // Disable terminal echo BEFORE displaying the prompt, including fast paste.
    crossterm::terminal::enable_raw_mode()?;
    struct RestoreTerminal;
    impl Drop for RestoreTerminal {
        fn drop(&mut self) {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
    let restore = RestoreTerminal;
    let value = rpassword::prompt_password(prompt);
    drop(restore);
    value.map(Zeroizing::new).map_err(|e| {
        if e.kind() == io::ErrorKind::Interrupted {
            Error::Cancelled
        } else {
            Error::Io(e)
        }
    })
}
fn execute(args: Args) -> Result<(), Error> {
    let (input, output, operation) = match args.command {
        Commands::Encrypt {
            input,
            output,
            algorithm,
        } => (input, output, Operation::Encrypt(algorithm.into())),
        Commands::Decrypt { input, output } => (input, Some(output), Operation::Decrypt),
        Commands::Verify { input } => (input, None, Operation::Verify),
    };
    if !io::stdin().is_terminal() {
        return Err(Error::Format(
            "비대화형 실행은 지원하지 않습니다. 터미널에서 실행하세요",
        ));
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))
        .map_err(|_| Error::Resource)?;
    let password = prompt_secret("비밀번호: ")?;
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    if matches!(operation, Operation::Encrypt(_)) {
        let confirmation = prompt_secret("비밀번호 확인: ")?;
        if *password != *confirmation {
            return Err(Error::Format("비밀번호 확인이 일치하지 않습니다"));
        }
        let name = input.file_name().and_then(|v| v.to_str());
        if name.is_none() {
            eprintln!("알림: UTF-8 파일명이 아니므로 이름 메타데이터를 생략합니다.");
        }
    }
    let mut last = None;
    let mut tick = Instant::now();
    let mut observer = |p: withcrypt_core::Progress| {
        if last != Some(p.stage) || tick.elapsed() > Duration::from_millis(500) {
            let label = match p.stage {
                Stage::Kdf => "키 파생",
                Stage::Processing => "처리",
                Stage::Verifying => "검증",
                Stage::Committing => "저장",
                Stage::Complete => "완료",
            };
            eprintln!("{label}: {} 바이트", p.bytes);
            last = Some(p.stage);
            tick = Instant::now();
        }
        !cancelled.load(Ordering::Relaxed)
    };
    let result = if operation == Operation::Decrypt {
        files::decrypt_into(
            &input,
            output.as_deref().ok_or(Error::Format("출력 디렉터리"))?,
            password.as_bytes(),
            &mut observer,
        )
    } else {
        files::run(
            &input,
            output.as_deref(),
            password.as_bytes(),
            operation,
            &mut observer,
        )
    }?;
    if matches!(operation, Operation::Encrypt(_)) && result.filename.is_empty() {
        eprintln!(
            "원본 파일명은 이식 가능한 UTF-8 이름이 아니어서 생략했습니다. GUI에서 복원 파일명을 지정하세요."
        );
    }
    println!(
        "성공: {} / {} 바이트",
        result.suite.name(),
        result.original_size
    );
    Ok(())
}
fn main() {
    if let Err(e) = execute(Args::parse()) {
        eprintln!("{e}");
        std::process::exit(e.exit_code());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arguments() {
        assert!(matches!(
            Args::try_parse_from(["withcrypt", "encrypt", "in"])
                .unwrap()
                .command,
            Commands::Encrypt { output: None, .. }
        ));
        assert!(Args::try_parse_from(["withcrypt", "decrypt", "in"]).is_err());
        let parsed =
            Args::try_parse_from(["withcrypt", "encrypt", "in", "--output", "out.esb"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Encrypt {
                algorithm: Algorithm::Xchacha20Poly1305,
                ..
            }
        ));
        assert!(
            Args::try_parse_from([
                "withcrypt",
                "encrypt",
                "in",
                "--output",
                "out",
                "--algorithm",
                "aes-256-gcm"
            ])
            .is_ok()
        );
        assert!(
            Args::try_parse_from(["withcrypt", "verify", "in", "--algorithm", "aes-256-gcm"])
                .is_err()
        );
        assert!(
            Args::try_parse_from([
                "withcrypt",
                "encrypt",
                "in",
                "--output",
                "out",
                "--algorithm",
                "bad"
            ])
            .is_err()
        );
    }
}
