#![forbid(unsafe_code)]
//! ESB v1 streaming primitives. Stream decryption writes authenticated chunks,
//! but callers must quarantine output until the entire operation succeeds.
//! Prefer [`files::run`] for transactional file output.
mod crypto;
pub mod files;
pub mod format;
mod stream;

pub use format::{CHUNK_SIZE, Header, Suite};
use std::io;
pub use stream::{decrypt, encrypt, verify};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("지원하지 않는 ESB 형식: {0}")]
    Format(&'static str),
    #[error("비밀번호가 올바르지 않거나 파일이 손상되었습니다")]
    Authentication,
    #[error("비밀번호는 비어 있을 수 없습니다")]
    EmptyPassword,
    #[error("저장된 원본 파일명이 없습니다. GUI에서 복호화할 파일명을 직접 지정하세요")]
    MissingFilename,
    #[error("I/O 오류: {0}")]
    Io(#[from] io::Error),
    #[error("키 파생 또는 난수 생성 자원 오류")]
    Resource,
    #[error("사용자가 취소했습니다")]
    Cancelled,
    #[error("입력 파일이 처리 중 변경되었습니다")]
    InputChanged,
    #[error("출력 파일이 이미 존재하거나 입력 파일과 같습니다")]
    OutputExists,
    #[error("출력 파일이 처리 중 다른 파일로 바뀌었습니다")]
    OutputChanged,
    #[error("미완성 출력 파일 정리 실패: {0}")]
    Cleanup(String),
}
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Format(_) | Self::EmptyPassword | Self::MissingFilename => 2,
            Self::Authentication => 3,
            Self::Cancelled => 130,
            _ => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Kdf,
    Processing,
    Verifying,
    Committing,
    Complete,
}
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub stage: Stage,
    pub bytes: u64,
}
/// Return false to cancel. KDF cancellation is checked before and after Argon2.
pub type Observer<'a> = dyn FnMut(Progress) -> bool + 'a;
pub(crate) fn notify(observer: &mut Observer<'_>, stage: Stage, bytes: u64) -> Result<()> {
    if observer(Progress { stage, bytes }) {
        Ok(())
    } else {
        Err(Error::Cancelled)
    }
}

#[derive(Debug, Clone)]
pub struct Summary {
    pub suite: Suite,
    pub original_size: u64,
    pub data_chunks: u64,
    /// Authenticated basename. Use files::PreparedDecryption for safe output selection.
    pub filename: String,
}
