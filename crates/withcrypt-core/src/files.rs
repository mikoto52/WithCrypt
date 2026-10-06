//! Shared CLI/desktop transactions. Output is written in place and removed unless
//! the whole operation, including final authentication, succeeds.
//!
//! Guarantees: the input is never modified; an existing file is never
//! overwritten; a failed, cancelled or unauthenticated run leaves no output.
use crate::*;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, BufReader, Write},
    path::{Path, PathBuf},
};

/// What [`run`] should do with the input file.
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

/// Fails with `InputChanged` if the input was modified, replaced or renamed
/// since it was opened. It compares size, modification time and file identity
/// (plus ctime on Unix). This catches ordinary concurrent edits; it is not a
/// snapshot and cannot see a change that restores every one of these values.
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

/// Windows: limit the new output file to the current user before any content
/// is written (Unix gets the same effect from mode 0600 at creation).
/// Inherited permissions are removed and only the process SID gets access.
#[cfg(windows)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // Query the process identity, never an environment-supplied account name.
    let identity = Command::new("whoami.exe")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["/user", "/fo", "csv", "/nh"])
        .output()?;
    if !identity.status.success() {
        return Err(Error::Resource);
    }
    // Output looks like "DOMAIN\user","S-1-5-21-..."; take the last field.
    let text = String::from_utf8_lossy(&identity.stdout);
    let sid = text
        .trim()
        .split(',')
        .next_back()
        .ok_or(Error::Resource)?
        .trim_matches('"');
    // Only pass a well-formed SID on to icacls.
    if !sid.starts_with("S-1-")
        || !sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
    {
        return Err(Error::Resource);
    }
    let grant = format!("*{sid}:F");
    let result = Command::new("icacls.exe")
        .creation_flags(CREATE_NO_WINDOW)
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant])
        .output()?;
    if !result.status.success() {
        return Err(Error::Resource);
    }
    Ok(())
}
#[cfg(not(windows))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

/// Append .esb without removing the input extension, including non-UTF-8 paths.
pub fn encrypted_path(input: &Path) -> Result<PathBuf> {
    let mut name = input
        .file_name()
        .ok_or(Error::Format("입력 파일명"))?
        .to_os_string();
    name.push(".esb");
    Ok(input.with_file_name(name))
}
/// Opens a regular file (not a directory or device) and records its metadata
/// so later checks can tell whether it changed.
fn open_input(input: &Path) -> Result<(File, Metadata)> {
    if !fs::metadata(input)?.is_file() {
        return Err(Error::Format("일반 파일만 지원합니다"));
    }
    let file = File::open(input)?;
    // Check again on the opened handle, in case the path changed in between.
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(Error::Format("일반 파일만 지원합니다"));
    }
    Ok((file, before))
}
/// Holds the same open input and derived keys between name authentication and save.
/// No plaintext output exists yet. Dropping this value cancels the prepared operation.
pub struct PreparedDecryption {
    input: PathBuf,
    before: Metadata,
    reader: BufReader<File>,
    state: stream::Decryption,
}
impl PreparedDecryption {
    /// Only META has been authenticated; the whole file still needs validation.
    pub fn filename(&self) -> &str {
        &self.state.filename
    }
    /// Resolve the authenticated basename in an existing user-selected directory.
    pub fn output_in(&self, directory: &Path) -> Result<PathBuf> {
        if self.filename().is_empty() {
            return Err(Error::MissingFilename);
        }
        format::validate_filename(self.filename())?;
        if !directory.is_dir() {
            return Err(Error::Format("--output은 기존 출력 디렉터리여야 합니다"));
        }
        Ok(fs::canonicalize(directory)?.join(self.filename()))
    }
    /// Explicit file destination, including a GUI-selected replacement filename.
    pub fn save(mut self, output: &Path, observer: &mut Observer<'_>) -> Result<Summary> {
        let source = self.reader.get_ref().try_clone()?;
        // The user may have spent a while in the save dialog; re-check the input.
        check_unchanged(&source, &self.input, &self.before)?;
        output_transaction(
            &self.input,
            &source,
            &self.before,
            output,
            observer,
            |writer, observer| self.state.finish(&mut self.reader, writer, observer),
        )
    }
}
/// First half of decryption: derive keys and authenticate the stored filename.
/// A wrong password fails here without creating any file.
pub fn prepare_decryption(
    input: &Path,
    password: &[u8],
    observer: &mut Observer<'_>,
) -> Result<PreparedDecryption> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    // Freeze relative paths before the GUI opens a native save dialog.
    let input = fs::canonicalize(input)?;
    let (file, before) = open_input(&input)?;
    let mut reader = BufReader::new(file);
    let state = stream::Decryption::begin(&mut reader, password, observer)?;
    check_unchanged(reader.get_ref(), &input, &before)?;
    Ok(PreparedDecryption {
        input,
        before,
        reader,
        state,
    })
}
/// CLI restore: --output is a directory, filename comes only from authenticated META.
pub fn decrypt_into(
    input: &Path,
    directory: &Path,
    password: &[u8],
    observer: &mut Observer<'_>,
) -> Result<Summary> {
    let prepared = prepare_decryption(input, password, observer)?;
    let output = prepared.output_in(directory)?;
    prepared.save(&output, observer)
}
/// Transactional file API. Encryption defaults to <input filename>.esb.
/// Decrypt here accepts an explicit filename; use decrypt_into for CLI directories.
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
    if operation == Operation::Decrypt {
        return prepare_decryption(input, password, observer)?.save(
            output.ok_or(Error::Format("출력 경로가 필요합니다"))?,
            observer,
        );
    }
    let (file, before) = open_input(input)?;
    let source = file.try_clone()?;
    let mut reader = BufReader::new(file);
    if operation == Operation::Verify {
        // Verify writes nothing, so it needs no output transaction.
        let summary = verify(&mut reader, password, observer)?;
        check_unchanged(reader.get_ref(), input, &before)?;
        notify(observer, Stage::Verifying, summary.original_size)?;
        observer(Progress {
            stage: Stage::Complete,
            bytes: summary.original_size,
        });
        return Ok(summary);
    }
    let default_output;
    let output = match output {
        Some(path) => path,
        None => {
            default_output = encrypted_path(input)?;
            &default_output
        }
    };
    let Operation::Encrypt(suite) = operation else {
        return Err(Error::Format("암호화 작업"));
    };
    // Store the original name only if it is portable; otherwise store none
    // and let the user choose a name when decrypting.
    let name = input.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let name = if format::validate_filename(name).is_ok() {
        name
    } else {
        ""
    };
    output_transaction(
        input,
        &source,
        &before,
        output,
        observer,
        |writer, observer| encrypt(&mut reader, writer, password, suite, name, observer),
    )
}
/// Creates `output`, lets `process` write into it, and keeps it only if every
/// step succeeds (ADR-005). Steps:
/// 1. Exclusively create the file (never overwrite) and restrict its access.
/// 2. Run `process` (encrypt, or decrypt including final authentication).
/// 3. Re-check the input, flush and fsync, report `Committing`, re-check again.
/// 4. Confirm the path still names the file we created.
///
/// Any failure removes the partial file. Success is final.
fn output_transaction(
    input: &Path,
    source: &File,
    before: &Metadata,
    output: &Path,
    observer: &mut Observer<'_>,
    process: impl FnOnce(&mut File, &mut Observer<'_>) -> Result<Summary>,
) -> Result<Summary> {
    notify(observer, Stage::Processing, 0)?;
    // Resolve the parent directory once so later checks use a stable path.
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    let output = parent.join(output.file_name().ok_or(Error::Format("출력 파일명"))?);
    // create_new is an atomic no-clobber create. It also refuses an existing
    // symlink or hard link alias, including the input itself.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&output).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            Error::OutputExists
        } else {
            Error::Io(e)
        }
    })?;
    // Identity of the file we just created, used to avoid deleting or
    // trusting a different file that later appears at the same path.
    let created = file_path_handle(&file)?;
    let result: Result<Summary> = (|| {
        restrict_file(&output)?;
        let summary = process(&mut file, observer)?;
        check_unchanged(source, input, before)?;
        file.flush()?;
        file.sync_all()?;
        notify(observer, Stage::Committing, summary.original_size)?;
        check_unchanged(source, input, before)?;
        if same_file::Handle::from_path(&output)? != created {
            return Err(Error::OutputChanged);
        }
        Ok(summary)
    })();
    // Close our handle before any removal (required on Windows).
    drop(file);
    let summary = match result {
        Ok(summary) => summary,
        Err(e) => {
            // The partial output is unverified. Remove it only while the path
            // still names the file this transaction created.
            return match remove_partial(&output, &created) {
                Ok(()) => Err(e),
                Err(cleanup) => Err(Error::Cleanup(format!("{cleanup}; 작업 결과: {e}"))),
            };
        }
    };
    // After commit, cancellation never removes the saved file.
    // On Unix, also fsync the directory so the new name survives a crash.
    #[cfg(unix)]
    File::open(&parent)?
        .sync_all()
        .map_err(|e| Error::Cleanup(format!("결과는 저장됨; 디렉터리 동기화 실패: {e}")))?;
    observer(Progress {
        stage: Stage::Complete,
        bytes: summary.original_size,
    });
    Ok(summary)
}
/// Deletes the unfinished output, but only if `output` is still the exact
/// file this run created.
fn remove_partial(output: &Path, created: &same_file::Handle) -> io::Result<()> {
    match same_file::Handle::from_path(output) {
        Ok(current) if current == *created => {
            drop(current);
            fs::remove_file(output)
        }
        // Replaced or already removed by another process: not ours to delete.
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
