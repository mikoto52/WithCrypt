use crate::{Error, Result};

pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;
pub const MAGIC: [u8; 8] = *b"ESB\0\r\n\x1a\n";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Suite {
    #[default]
    XChaCha20Poly1305,
    Aes256Gcm,
}
impl Suite {
    pub fn id(self) -> u16 {
        match self {
            Self::XChaCha20Poly1305 => 1,
            Self::Aes256Gcm => 2,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::XChaCha20Poly1305 => "xchacha20-poly1305",
            Self::Aes256Gcm => "aes-256-gcm",
        }
    }
}

#[derive(Clone)]
pub struct Header {
    pub(crate) raw: [u8; 64],
    pub suite: Suite,
}
impl Header {
    pub(crate) fn new(suite: Suite, salt: [u8; 16], prefix: [u8; 16]) -> Self {
        let mut raw = [0; 64];
        raw[..8].copy_from_slice(&MAGIC);
        for (offset, value) in [(8, 1u16), (10, 64), (12, suite.id()), (14, 0)] {
            raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(16, 65536u32), (20, 3), (24, 4), (28, CHUNK_SIZE as u32)] {
            raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        raw[32..48].copy_from_slice(&salt);
        raw[48..].copy_from_slice(&prefix);
        Self { raw, suite }
    }
    /// Bounded, KDF-free validation suitable for fuzzing and untrusted previews.
    pub fn parse(raw: [u8; 64]) -> Result<Self> {
        if raw[..8] != MAGIC {
            return Err(Error::Format("magic"));
        }
        let suite = match u16::from_le_bytes([raw[12], raw[13]]) {
            1 => Suite::XChaCha20Poly1305,
            2 => Suite::Aes256Gcm,
            _ => return Err(Error::Format("suite")),
        };
        let expected = Self::new(suite, [0; 16], [0; 16]);
        if raw[..32] != expected.raw[..32] {
            return Err(Error::Format("버전/헤더/KDF/청크 설정"));
        }
        Ok(Self { raw, suite })
    }
    pub fn bytes(&self) -> &[u8; 64] {
        &self.raw
    }
    pub(crate) fn salt(&self) -> &[u8] {
        &self.raw[32..48]
    }
    pub(crate) fn prefix(&self) -> &[u8] {
        &self.raw[48..64]
    }
}

#[derive(Debug)]
pub struct RecordHeader {
    pub kind: u8,
    pub index: u64,
    pub len: usize,
}
impl RecordHeader {
    pub fn parse(raw: [u8; 13], expected: u64) -> Result<Self> {
        let index = u64::from_le_bytes(raw[1..9].try_into().map_err(|_| Error::Authentication)?);
        let len =
            u32::from_le_bytes(raw[9..13].try_into().map_err(|_| Error::Authentication)?) as usize;
        let valid = match raw[0] {
            1 => index == 0 && (2..=4098).contains(&len),
            2 => index > 0 && (1..=CHUNK_SIZE).contains(&len),
            3 => index > 0 && len == 48,
            _ => false,
        };
        if index != expected || !valid {
            return Err(Error::Authentication);
        }
        Ok(Self {
            kind: raw[0],
            index,
            len,
        })
    }
    pub(crate) fn bytes(&self) -> [u8; 13] {
        let mut raw = [0; 13];
        raw[0] = self.kind;
        raw[1..9].copy_from_slice(&self.index.to_le_bytes());
        raw[9..].copy_from_slice(&(self.len as u32).to_le_bytes());
        raw
    }
}
pub(crate) fn increment(value: u64) -> Result<u64> {
    value.checked_add(1).ok_or(Error::Authentication)
}

pub(crate) fn validate_filename(name: &str) -> Result<()> {
    if name.len() > 4096
        || name.contains(['/', '\\', ':', '<', '>', '"', '|', '?', '*'])
        || name.chars().any(char::is_control)
        || name == "."
        || name == ".."
        || name.ends_with(['.', ' '])
    {
        return Err(Error::Format("안전하지 않은 파일명"));
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    if ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        || ["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"].contains(&stem.as_str())
    {
        return Err(Error::Format("예약 파일명"));
    }
    Ok(())
}
