//! Windows 11 top-level menu: the WithCrypt sparse package (manifest + logos)
//! whose external location holds withcrypt-gui.exe and withcrypt_shell.dll.
//! Until code signing is set up, the package is built unsigned with Microsoft's
//! test-only publisher OID and installed with `Add-AppxPackage -AllowUnsigned`.
use std::{path::Path, process::Command};
use windows_registry::LOCAL_MACHINE;

/// Identity name from AppxManifest.xml.
pub const PACKAGE_NAME: &str = "WithCrypt.ShellExtension";
/// Package file produced by scripts/package-windows-shell.ps1.
pub const PACKAGE_FILE: &str = "WithCrypt.Shell.msix";
/// Windows 11 starts at build 22000; earlier builds have no top-level menu.
const FIRST_SUPPORTED_BUILD: u32 = 22000;

/// Windows build number from the registry (e.g. 26100).
pub fn windows_build() -> Option<u32> {
    LOCAL_MACHINE
        .open(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .and_then(|key| key.get_string("CurrentBuildNumber"))
        .ok()?
        .parse()
        .ok()
}

/// True on Windows 11, where the top-level menu exists.
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
    if !text.is_empty() {
        return Ok(Some(text));
    }
    // An unsigned package installed from an elevated prompt is hidden from a
    // non-elevated Get-AppxPackage, but its packaged COM registration (which
    // Explorer uses) is still visible to the user.
    Ok(packaged_com_registration().map(|name| format!("{name} (관리자 권한 설치)")))
}

/// Full package name from the user's packaged COM catalog, if registered.
fn packaged_com_registration() -> Option<String> {
    let prefix = format!("{PACKAGE_NAME}_");
    windows_registry::CURRENT_USER
        .open(r"Software\Classes\PackagedCom\Package")
        .ok()?
        .keys()
        .ok()?
        .find(|name| name.starts_with(&prefix))
}

/// Installs the package with this folder as its external location.
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

/// Removes the package for the current user; nothing to do if it is not installed.
pub fn unregister() -> Result<(), String> {
    powershell(&format!(
        "Get-AppxPackage -Name {} | Remove-AppxPackage",
        ps_quote(PACKAGE_NAME)
    ))
    .map_err(explain)?;
    // Get-AppxPackage cannot see an elevated install, so the pipeline above
    // silently removes nothing. Report it instead of claiming success.
    if registered() {
        return Err(
            "관리자 권한으로 설치된 패키지라 지금 권한으로는 해제할 수 없습니다. \
             관리자 권한 명령 프롬프트에서 다시 실행하세요."
                .into(),
        );
    }
    Ok(())
}

/// True while Explorer can still see the package's menu registration.
pub fn registered() -> bool {
    packaged_com_registration().is_some()
}

/// Adds a hint to PowerShell errors that usually mean "run as administrator".
fn explain(error: String) -> String {
    // 0x80073D2B: an unsigned package with an executable activation (ours has
    // one: the Application entry) installs only for all users, i.e. elevated.
    if error.contains("0x80073D2B") {
        "서명되지 않은 패키지는 관리자 권한에서만 설치할 수 있습니다 (0x80073D2B). \
         Windows 11 새 메뉴가 필요하면 관리자 권한 명령 프롬프트에서 다시 실행하거나 \
         서명된 패키지를 사용하세요."
            .to_owned()
    // 0x80073CF9 / 0x80070005: unsigned packages with code may need an elevated shell.
    } else if error.contains("0x80070005") || error.contains("0x80073CF9") {
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
