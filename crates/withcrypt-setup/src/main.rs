#![forbid(unsafe_code)]
//! Registers both classic and Windows 11 WithCrypt Explorer menus (ADR-004).
//! Expects withcrypt-gui.exe, withcrypt_shell.dll and WithCrypt.Shell.msix
//! in the same folder as this executable.
#[cfg(windows)]
mod classic;
#[cfg(windows)]
mod modern;

/// Printed for unknown or missing arguments.
const USAGE: &str = "\
사용법: withcrypt-setup <명령>

  register     Windows 11 새 메뉴 등록 (실패 시 클래식 메뉴)
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
    let gui = dir.join("withcrypt-gui.exe");
    let shell_icon = dir.join("ShellIcon.ico");
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
            if !gui.is_file() {
                eprintln!("{}이(가) 없습니다.", gui.display());
                return false;
            }
            if !shell_icon.is_file() {
                eprintln!("{}이(가) 없습니다.", shell_icon.display());
                return false;
            }
            if classic_only {
                // Best effort: even if an elevated modern package cannot be
                // removed here, still make the requested classic menu usable.
                let modern_ok =
                    !modern::supported() || report("Windows 11 새 메뉴 해제", modern::unregister());
                let classic_ok = report("클래식 메뉴", classic::register(&gui, &shell_icon));
                if classic_ok {
                    println!("메뉴가 바로 보이지 않으면 탐색기를 다시 시작하세요.");
                }
                return modern_ok && classic_ok;
            }
            // Install classic first as a fallback. A successful packaged verb
            // also appears in the classic surface, so remove the registry copy
            // afterward to avoid duplicate decrypt commands.
            let classic_ok = report("클래식 메뉴", classic::register(&gui, &shell_icon));
            if !modern::supported() {
                println!("[건너뜀] Windows 11 새 메뉴: Windows 11에서만 지원합니다");
                return classic_ok;
            }
            let package = dir.join(modern::PACKAGE_FILE);
            // The package points Explorer at the DLL, so both must be present.
            let missing = [package.clone(), dir.join("withcrypt_shell.dll")]
                .into_iter()
                .find(|path| !path.is_file());
            let modern_ok = report(
                "Windows 11 새 메뉴",
                match missing {
                    Some(path) => Err(format!("{}이(가) 없습니다", path.display())),
                    None => modern::register(&package, &dir),
                },
            );
            if modern_ok {
                let classic_removed = report("중복 클래식 메뉴 해제", classic::unregister());
                // Explorer loads packaged menu extensions only when it starts.
                println!("새 메뉴는 탐색기를 다시 시작하거나 다시 로그인해야 나타납니다.");
                return classic_removed;
            } else if classic_ok {
                println!("메뉴가 바로 보이지 않으면 탐색기를 다시 시작하세요.");
            }
            classic_ok
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
