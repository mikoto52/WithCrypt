//! Classic Explorer context menu entries under HKCU. No administrator rights.
//! Windows 11 shows these under "Show more options"; the packaged
//! `withcrypt-shell` COM handler covers the new top-level menu.
use std::path::Path;
use windows_registry::CURRENT_USER;

pub struct Entry {
    pub key: &'static str,
    pub title: &'static str,
    pub flag: &'static str,
    pub applies_to: Option<&'static str>,
}

/// Every file except `.esb` gets Encrypt; only `.esb` gets Decrypt.
/// SystemFileAssociations keeps any existing `.esb` default program intact.
pub const ENTRIES: [Entry; 2] = [
    Entry {
        key: r"Software\Classes\*\shell\WithCrypt.Encrypt",
        title: "WithCrypt로 암호화",
        flag: "--encrypt",
        applies_to: Some("NOT System.FileExtension:=.esb"),
    },
    Entry {
        key: r"Software\Classes\SystemFileAssociations\.esb\shell\WithCrypt.Decrypt",
        title: "WithCrypt로 복호화",
        flag: "--decrypt",
        applies_to: None,
    },
];
const NOT_FOUND: i32 = 0x8007_0002_u32 as i32;

pub fn command_line(exe: &str, flag: &str) -> String {
    format!("\"{exe}\" {flag} \"%1\"")
}

fn exe_string(exe: &Path) -> Result<&str, String> {
    let exe = exe
        .to_str()
        .ok_or("실행 파일 경로가 UTF-8이 아니어서 등록할 수 없습니다")?;
    if exe.contains('"') {
        return Err("실행 파일 경로에 큰따옴표가 있어 등록할 수 없습니다".into());
    }
    Ok(exe)
}

pub fn register(desktop: &Path) -> Result<(), String> {
    let exe = exe_string(desktop)?;
    let result = (|| -> windows_registry::Result<()> {
        for entry in &ENTRIES {
            let key = CURRENT_USER.create(entry.key)?;
            key.set_string("MUIVerb", entry.title)?;
            key.set_string("Icon", format!("\"{exe}\",0"))?;
            if let Some(filter) = entry.applies_to {
                key.set_string("AppliesTo", filter)?;
            }
            CURRENT_USER
                .create(format!(r"{}\command", entry.key))?
                .set_string("", command_line(exe, entry.flag))?;
        }
        Ok(())
    })();
    result.map_err(|e| e.message())
}

pub fn unregister() -> Result<(), String> {
    for entry in &ENTRIES {
        match CURRENT_USER.remove_tree(entry.key) {
            Ok(()) => {}
            Err(e) if e.code().0 == NOT_FOUND => {}
            Err(e) => return Err(e.message()),
        }
    }
    Ok(())
}

/// The registered command line for the encrypt verb, if any.
pub fn registered_command() -> Option<String> {
    CURRENT_USER
        .open(format!(r"{}\command", ENTRIES[0].key))
        .and_then(|key| key.get_string(""))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_lines_quote_paths() {
        assert_eq!(
            command_line(
                r"C:\Program Files\WithCrypt\withcrypt-desktop.exe",
                "--encrypt"
            ),
            r#""C:\Program Files\WithCrypt\withcrypt-desktop.exe" --encrypt "%1""#
        );
        assert!(exe_string(Path::new(r#"C:\bad"name.exe"#)).is_err());
        assert!(ENTRIES[0].applies_to.unwrap().contains(".esb"));
        assert!(ENTRIES[1].key.contains(r"\.esb\"));
    }
}
