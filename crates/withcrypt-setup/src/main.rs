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
Usage: withcrypt-setup <command>

  register     Register the Windows 11 and classic menus
  register --classic-only
               Register only the classic menu ('Show more options')
  unregister   Unregister both menus
  status       Show registration status";

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
            eprintln!("Could not determine the executable location: {e}");
            return false;
        }
    };
    let gui = dir.join("withcrypt-gui.exe");
    let shell_icon = dir.join("ShellIcon.ico");
    let report = |label: &str, result: Result<(), String>| match result {
        Ok(()) => {
            println!("[OK] {label}");
            true
        }
        Err(e) => {
            eprintln!("[FAILED] {label}: {e}");
            false
        }
    };
    match command {
        Command::Register { classic_only } => {
            if !gui.is_file() {
                eprintln!("{} does not exist.", gui.display());
                return false;
            }
            if !shell_icon.is_file() {
                eprintln!("{} does not exist.", shell_icon.display());
                return false;
            }
            if classic_only {
                // Best effort: even if an elevated modern package cannot be
                // removed here, still make the requested classic menu usable.
                let modern_ok = !modern::supported()
                    || report("Unregister Windows 11 menu", modern::unregister());
                let classic_ok = report("Classic menu", classic::register(&gui, &shell_icon));
                if classic_ok {
                    println!("Restart File Explorer if the menu does not appear immediately.");
                }
                return modern_ok && classic_ok;
            }
            // Keep the registry command for "Show more options". The packaged
            // command supplies the Windows 11 surface but is not guaranteed to
            // be included in the classic surface.
            let classic_ok = report("Classic menu", classic::register(&gui, &shell_icon));
            if !modern::supported() {
                println!(
                    "[SKIPPED] Windows 11 menu: supported only by 64-bit (x64/ARM64) builds on Windows 11"
                );
                return classic_ok;
            }
            let package = dir.join(modern::PACKAGE_FILE);
            // The package points Explorer at the DLL, so both must be present.
            let missing = [package.clone(), dir.join("withcrypt_shell.dll")]
                .into_iter()
                .find(|path| !path.is_file());
            let modern_ok = report(
                "Windows 11 menu",
                match missing {
                    Some(path) => Err(format!("{} does not exist", path.display())),
                    None => modern::register(&package, &dir),
                },
            );
            if modern_ok {
                // Explorer loads packaged menu extensions only when it starts.
                println!("Restart File Explorer or sign in again to show the Windows 11 menu.");
                return classic_ok;
            } else if classic_ok {
                println!("Restart File Explorer if the menu does not appear immediately.");
            }
            classic_ok
        }
        Command::Unregister => {
            let mut ok = report("Unregister classic menu", classic::unregister());
            if modern::supported() {
                ok &= report("Unregister Windows 11 menu", modern::unregister());
            }
            ok
        }
        Command::Status => {
            match classic::registered_command() {
                Some(command) => println!("Classic menu: registered ({command})"),
                None => println!("Classic menu: not registered"),
            }
            if !modern::supported() {
                println!("Windows 11 menu: unsupported on this Windows version or 32-bit build");
                return true;
            }
            match modern::installed() {
                Ok(Some(info)) => println!("Windows 11 menu: installed ({info})"),
                Ok(None) => println!("Windows 11 menu: not installed"),
                Err(e) => {
                    eprintln!("Windows 11 menu: status check failed ({e})");
                    return false;
                }
            }
            true
        }
    }
}

#[cfg(not(windows))]
fn run(_command: Command) -> bool {
    eprintln!("Explorer menus are supported only on Windows.");
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
