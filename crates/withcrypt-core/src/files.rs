//! Shared CLI/desktop transactions. Output is published only after full validation.
use crate::*;
use std::{
    fs::{self, File, Metadata},
    io::{self, BufReader, Write},
    path::Path,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Encrypt(Suite),
    Decrypt,
    Verify,
}

// same-file handles compare open descriptors, avoiding path-only alias checks.
fn file_path_handle(file: &File) -> io::Result<same_file::Handle> {
    same_file::Handle::from_file(file.try_clone()?)
}

fn check_unchanged(file: &File, input: &Path, before: &Metadata) -> Result<()> {
    let after = file.metadata()?;
    let opened = file_path_handle(file)?;
    let current = same_file::Handle::from_path(input)?;
    if before.len() != after.len() || before.modified()? != after.modified()? || opened != current {
        return Err(Error::InputChanged);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() {
            return Err(Error::InputChanged);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::process::Command;
    // Query the process identity, never an environment-supplied account name.
    let identity = Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()?;
    if !identity.status.success() {
        return Err(Error::Resource);
    }
    let text = String::from_utf8_lossy(&identity.stdout);
    let sid = text
        .trim()
        .split(',')
        .next_back()
        .ok_or(Error::Resource)?
        .trim_matches('"');
    if !sid.starts_with("S-1-")
        || !sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
    {
        return Err(Error::Resource);
    }
    let grant = format!("*{sid}:(OI)(CI)F");
    let result = Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant])
        .output()?;
    if !result.status.success() {
        return Err(Error::Resource);
    }
    Ok(())
}
#[cfg(not(windows))]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}

/// No output overwrite or input deletion. The output argument is always explicit.
pub fn run(
    input: &Path,
    output: Option<&Path>,
    password: &[u8],
    operation: Operation,
    observer: &mut Observer<'_>,
) -> Result<Summary> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    if !fs::metadata(input)?.is_file() {
        return Err(Error::Format("일반 파일만 지원합니다"));
    }
    let file = File::open(input)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(Error::Format("일반 파일만 지원합니다"));
    }
    let mut reader = BufReader::new(file);
    if operation == Operation::Verify {
        let summary = verify(&mut reader, password, observer)?;
        check_unchanged(reader.get_ref(), input, &before)?;
        notify(observer, Stage::Verifying, summary.original_size)?;
        observer(Progress {
            stage: Stage::Complete,
            bytes: summary.original_size,
        });
        return Ok(summary);
    }
    let output = output.ok_or(Error::Format("출력 경로가 필요합니다"))?;
    match fs::symlink_metadata(output) {
        Ok(_) => return Err(Error::OutputExists),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    let output = parent.join(output.file_name().ok_or(Error::Format("출력 파일명"))?);
    let mut builder = tempfile::Builder::new();
    builder.prefix(".withcrypt-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    let tempdir = builder.tempdir_in(&parent)?;
    let result: Result<Summary> = (|| {
        restrict_directory(tempdir.path())?;
        let mut temp = tempfile::NamedTempFile::new_in(tempdir.path())?;
        let name = input.file_name().and_then(|s| s.to_str()).unwrap_or("");
        // Optional metadata: omit names not representable safely on all targets.
        let name = if format::validate_filename(name).is_ok() {
            name
        } else {
            ""
        };
        let summary = match operation {
            Operation::Encrypt(suite) => {
                encrypt(&mut reader, &mut temp, password, suite, name, observer)?
            }
            Operation::Decrypt => decrypt(&mut reader, &mut temp, password, observer)?,
            Operation::Verify => unreachable!(),
        };
        check_unchanged(reader.get_ref(), input, &before)?;
        temp.flush()?;
        temp.as_file().sync_all()?;
        notify(observer, Stage::Committing, summary.original_size)?;
        check_unchanged(reader.get_ref(), input, &before)?;
        // hard_link creates the destination atomically and fails if it exists.
        // The temp file is on the same filesystem. No check-then-rename fallback.
        fs::hard_link(temp.path(), &output).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                Error::OutputExists
            } else {
                Error::Io(e)
            }
        })?;
        // After commit, cancellation never removes the published file.
        temp.close()
            .map_err(|e| Error::Cleanup(format!("결과는 저장됨; {e}")))?;
        #[cfg(unix)]
        File::open(&parent)?
            .sync_all()
            .map_err(|e| Error::Cleanup(format!("결과는 저장됨; 디렉터리 동기화 실패: {e}")))?;
        Ok(summary)
    })();
    if let Err(e) = tempdir.close() {
        return Err(Error::Cleanup(format!(
            "{e}; 작업 결과: {}",
            if result.is_ok() {
                "저장됨".to_owned()
            } else {
                result
                    .as_ref()
                    .err()
                    .map(ToString::to_string)
                    .unwrap_or_default()
            }
        )));
    }
    let summary = result?;
    observer(Progress {
        stage: Stage::Complete,
        bytes: summary.original_size,
    });
    Ok(summary)
}
