#![forbid(unsafe_code)]
//! Registers or removes both WithCrypt Explorer menus (ADR-004).
//! Expects withcrypt-desktop.exe, withcrypt_shell.dll and WithCrypt.Shell.msix
//! in the same folder as this executable.
#[cfg(windows)]
mod classic;
#[cfg(windows)]
mod modern;

/// Printed for unknown or missing arguments.
const USAGE: &str = "\
사용법: withcrypt-shell-setup <명령>

  register     탐색기 메뉴 등록 (클래식 + Windows 11 새 메뉴)
  register --classic-only
               클래식 메뉴만 등록 ('더 많은 옵션 표시')
  unregister   두 메뉴 모두 해제
  status       등록 상태 표시";

#[derive(Debug, PartialEq)]
#[cfg_attr(not(windows), allow(dead_code))]
/// A parsed command line.
enum Command {
    Register { classic_only: bool },
    Unregister,
    Status,
}

/// Accepts exactly the forms listed in `USAGE`.
fn parse(args: &[String]) -> Option<Command> {
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["register"] => Some(Command::Register {
            classic_only: false,
        }),
        ["register", "--classic-only"] => Some(Command::Register { classic_only: true }),
        ["unregister"] => Some(Command::Unregister),
        ["status"] => Some(Command::Status),
        _ => None,
    }
}

#[cfg(windows)]
/// Executes a command and prints one line per step. Returns false on any failure.
fn run(command: Command) -> bool {
    use std::path::PathBuf;
    // Everything is resolved relative to this executable's folder.
    let dir = match std::env::current_exe() {
        Ok(exe) => exe.parent().map(PathBuf::from).unwrap_or_default(),
        Err(e) => {
            eprintln!("실행 위치를 알 수 없습니다: {e}");
            return false;
        }
    };
    let desktop = dir.join("withcrypt-desktop.exe");
    let report = |label: &str, result: Result<(), String>| match result {
        Ok(()) => {
            println!("[완료] {label}");
            true
        }
        Err(e) => {
            eprintln!("[실패] {label}: {e}");
            false
        }
    };
    match command {
        Command::Register { classic_only } => {
            if !desktop.is_file() {
                eprintln!("{}이(가) 없습니다.", desktop.display());
                return false;
            }
            let mut ok = report("클래식 메뉴", classic::register(&desktop));
            if classic_only {
                return ok;
            }
            if !modern::supported() {
                println!("[건너뜀] Windows 11 새 메뉴: Windows 11에서만 지원합니다");
                return ok;
            }
            let package = dir.join(modern::PACKAGE_FILE);
            // The package points Explorer at the DLL, so both must be present.
            let missing = [package.clone(), dir.join("withcrypt_shell.dll")]
                .into_iter()
                .find(|path| !path.is_file());
            ok &= report(
                "Windows 11 새 메뉴",
                match missing {
                    Some(path) => Err(format!("{}이(가) 없습니다", path.display())),
                    None => modern::register(&package, &dir),
                },
            );
            if ok {
                println!("메뉴가 바로 보이지 않으면 탐색기를 다시 시작하세요.");
            }
            ok
        }
        Command::Unregister => {
            let mut ok = report("클래식 메뉴 해제", classic::unregister());
            if modern::supported() {
                ok &= report("Windows 11 새 메뉴 해제", modern::unregister());
            }
            ok
        }
        Command::Status => {
            match classic::registered_command() {
                Some(command) => println!("클래식 메뉴: 등록됨 ({command})"),
                None => println!("클래식 메뉴: 등록 안 됨"),
            }
            if !modern::supported() {
                println!("Windows 11 새 메뉴: 지원하지 않는 Windows");
                return true;
            }
            match modern::installed() {
                Ok(Some(info)) => println!("Windows 11 새 메뉴: 설치됨 ({info})"),
                Ok(None) => println!("Windows 11 새 메뉴: 설치 안 됨"),
                Err(e) => {
                    eprintln!("Windows 11 새 메뉴: 확인 실패 ({e})");
                    return false;
                }
            }
            true
        }
    }
}

#[cfg(not(windows))]
fn run(_command: Command) -> bool {
    eprintln!("탐색기 메뉴는 Windows 전용입니다.");
    false
}

/// Exit codes: 0 = success, 1 = a step failed, 2 = bad arguments.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = parse(&args) else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };
    if !run(command) {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arguments() {
        let parse = |v: &[&str]| parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(
            parse(&["register"]),
            Some(Command::Register {
                classic_only: false
            })
        );
        assert_eq!(
            parse(&["register", "--classic-only"]),
            Some(Command::Register { classic_only: true })
        );
        assert_eq!(parse(&["unregister"]), Some(Command::Unregister));
        assert_eq!(parse(&["status"]), Some(Command::Status));
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&["register", "x"]), None);
    }
}
