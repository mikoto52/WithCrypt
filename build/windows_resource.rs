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

fn numeric_version(version: &str) -> [u16; 4] {
    let mut result = [0; 4];
    for (slot, component) in result.iter_mut().zip(version.split('.')) {
        let digits = component
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        *slot = digits.parse().unwrap_or(0);
    }
    result
}

/// Embeds Windows VERSIONINFO and, optionally, the application icon.
pub fn compile(binary: &str, product_name: &str, original_filename: &str, icon: Option<&str>) {
    println!("cargo:rerun-if-changed=../../build/windows_resource.rs");
    if let Some(icon) = icon {
        println!("cargo:rerun-if-changed={icon}");
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let icon_line = icon.map_or_else(String::new, |relative| {
        fs::copy(manifest.join(relative), out.join("application.ico"))
            .expect("Windows 아이콘 파일을 읽을 수 없습니다");
        "1 ICON \"application.ico\"\n".to_owned()
    });
    let version = env::var("CARGO_PKG_VERSION").expect("package version");
    let [major, minor, patch, build] = numeric_version(&version);
    let resource_script = format!(
        r#"#pragma code_page(65001)
#include <windows.h>
{icon_line}1 VERSIONINFO
FILEVERSION {major},{minor},{patch},{build}
PRODUCTVERSION {major},{minor},{patch},{build}
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName", "TeamAST\0"
            VALUE "FileDescription", "{product_name}\0"
            VALUE "FileVersion", "{version}\0"
            VALUE "InternalName", "{binary}\0"
            VALUE "LegalCopyright", "ⓒ TeamAST. All rights reserved\0"
            VALUE "OriginalFilename", "{original_filename}\0"
            VALUE "ProductName", "{product_name}\0"
            VALUE "ProductVersion", "{version}\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
"#
    );
    let script = out.join(format!("{binary}.rc"));
    fs::write(&script, resource_script).expect("Windows resource script");
    let resource = out.join(format!("{binary}.res"));

    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let status = if target_env == "msvc" {
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
    assert!(status.success(), "Windows 리소스 컴파일 실패");
    println!("cargo:rustc-link-arg-bin={binary}={}", resource.display());
}
