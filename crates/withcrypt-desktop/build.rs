use std::{env, fs, path::PathBuf, process::Command};

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
    let script = out.join("withcrypt-desktop.rc");
    fs::write(&script, "1 ICON \"AppIcon2.ico\"\n").expect("resource script");
    let resource = out.join("withcrypt-desktop.res");

    let env_name = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let status = if env_name == "msvc" {
        Command::new("rc.exe")
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
        "cargo:rustc-link-arg-bin=withcrypt-desktop={}",
        resource.display()
    );
}
