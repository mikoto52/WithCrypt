//! Windows 11 top-level menu: the WithCrypt sparse package (manifest + logos)
//! whose external location holds withcrypt-desktop.exe and withcrypt_shell.dll.
//! Until code signing is set up, the package is built unsigned with Microsoft's
//! test-only publisher OID and installed with `Add-AppxPackage -AllowUnsigned`.
use std::{path::Path, process::Command};
use windows_registry::LOCAL_MACHINE;

pub const PACKAGE_NAME: &str = "WithCrypt.ShellExtension";
pub const PACKAGE_FILE: &str = "WithCrypt.Shell.msix";
/// Windows 11 starts at build 22000; earlier builds have no top-level menu.
const FIRST_SUPPORTED_BUILD: u32 = 22000;

pub fn windows_build() -> Option<u32> {
    LOCAL_MACHINE
        .open(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .and_then(|key| key.get_string("CurrentBuildNumber"))
        .ok()?
        .parse()
        .ok()
}

pub fn supported() -> bool {
    windows_build().is_some_and(|build| build >= FIRST_SUPPORTED_BUILD)
}

/// Single-quoted PowerShell literal: only `'` needs escaping (doubled).
pub fn ps_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// Runs a script; errors come back as UTF-8 text instead of the console codepage.
fn powershell(body: &str) -> Result<String, String> {
    let script = format!(
        "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; \
         [Console]::OutputEncoding = [Text.Encoding]::UTF8; \
         try {{ {body} }} catch {{ [Console]::Out.Write($_.Exception.Message); exit 1 }}"
    );
    let exe = std::env::var_os("SystemRoot")
        .map(|root| Path::new(&root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| "powershell.exe".into());
    let output = Command::new(exe)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
        ])
        .arg(script)
        .output()
        .map_err(|e| format!("PowerShell을 실행할 수 없습니다: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if output.status.success() {
        Ok(text)
    } else {
        Err(text)
    }
}

/// Installed package version and location, if any (current user).
pub fn installed() -> Result<Option<String>, String> {
    let text = powershell(&format!(
        "Get-AppxPackage -Name {} | ForEach-Object {{ \"$($_.Version) $($_.InstallLocation)\" }}",
        ps_quote(PACKAGE_NAME)
    ))?;
    Ok((!text.is_empty()).then_some(text))
}

pub fn register(package: &Path, external: &Path) -> Result<(), String> {
    let package = package.to_str().ok_or("패키지 경로가 UTF-8이 아닙니다")?;
    let external = external.to_str().ok_or("설치 경로가 UTF-8이 아닙니다")?;
    // Re-registering replaces an older registration pointing elsewhere.
    unregister()?;
    powershell(&format!(
        "Add-AppxPackage -Path {} -ExternalLocation {} -AllowUnsigned",
        ps_quote(package),
        ps_quote(external)
    ))
    .map(drop)
    .map_err(explain)
}

pub fn unregister() -> Result<(), String> {
    powershell(&format!(
        "Get-AppxPackage -Name {} | Remove-AppxPackage",
        ps_quote(PACKAGE_NAME)
    ))
    .map(drop)
    .map_err(explain)
}

fn explain(error: String) -> String {
    // 0x80073CF9 / 0x80070005: unsigned packages with code may need an elevated shell.
    if error.contains("0x80070005") || error.contains("0x80073CF9") {
        format!("{error}\n관리자 권한 명령 프롬프트에서 다시 실행해 보세요.")
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoting_and_build_detection() {
        assert_eq!(ps_quote(r"C:\it's here"), r"'C:\it''s here'");
        assert_eq!(ps_quote("a;b $x"), "'a;b $x'");
        assert!(windows_build().is_some_and(|build| build >= 10240));
    }
}
