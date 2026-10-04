use std::{env, fs, path::PathBuf, process::Command};

/// `rc.exe` is normally not on PATH in an ordinary PowerShell session. Locate
/// the newest x64 compiler in a standard Windows SDK installation instead.
fn msvc_resource_compiler() -> PathBuf {
    for variable in ["ProgramFiles(x86)", "ProgramFiles"] {
        let Some(program_files) = env::var_os(variable) else {
            continue;
        };
        let bin = PathBuf::from(program_files).join("Windows Kits/10/bin");
        let Ok(entries) = fs::read_dir(bin) else {
            continue;
        };
        let mut candidates = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("x64/rc.exe"))
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        candidates.sort();
        if let Some(path) = candidates.pop() {
            return path;
        }
    }
    PathBuf::from("rc.exe")
}

fn main() {
    println!("cargo:rerun-if-changed=../../resources/AppIcon2.ico");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let icon = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"))
        .join("../../resources/AppIcon2.ico");
    let copied_icon = out.join("AppIcon2.ico");
    fs::copy(&icon, &copied_icon).expect("resources/AppIcon2.ico를 읽을 수 없습니다");
    let script = out.join("withcrypt-gui.rc");
    fs::write(&script, "1 ICON \"AppIcon2.ico\"\n").expect("resource script");
    let resource = out.join("withcrypt-gui.res");

    let env_name = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let status = if env_name == "msvc" {
        Command::new(msvc_resource_compiler())
            .current_dir(&out)
            .arg("/nologo")
            .arg(format!("/fo{}", resource.display()))
            .arg(&script)
            .status()
    } else {
        Command::new("windres")
            .current_dir(&out)
            .args(["-O", "coff", "-i"])
            .arg(&script)
            .arg("-o")
            .arg(&resource)
            .status()
    }
    .expect("Windows resource compiler를 실행할 수 없습니다");
    assert!(status.success(), "Windows 아이콘 리소스 컴파일 실패");
    println!(
        "cargo:rustc-link-arg-bin=withcrypt-gui={}",
        resource.display()
    );
}
