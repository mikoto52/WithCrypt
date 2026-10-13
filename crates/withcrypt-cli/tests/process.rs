#![forbid(unsafe_code)]
use std::process::{Command, Stdio};
#[test]
fn rejects_noninteractive_and_algorithm_override() {
    let exe = env!("CARGO_BIN_EXE_withcrypt");
    let result = Command::new(exe)
        .args(["verify", "missing.esb"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("비대화형"));
    let result = Command::new(exe)
        .args([
            "decrypt",
            "in.esb",
            "--output",
            "out",
            "--algorithm",
            "aes-256-gcm",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
}
