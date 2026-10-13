//! ESB v1 container layout: the fixed 64-byte header, 13-byte record
//! headers, and the rules for the restored filename (see docs/format-v1.md).
use crate::{Error, Result};

/// Plaintext bytes per DATA record. Only the last DATA record may be shorter.
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// File signature. The CR LF and Ctrl-Z bytes detect text-mode transfer damage.
pub const MAGIC: [u8; 8] = *b"ESB\0\r\n\x1a\n";

/// The AEAD algorithm chosen at encryption time and recorded in the header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Suite {
    #[default]
    XChaCha20Poly1305,
    Aes256Gcm,
}
impl Suite {
    /// The `suite_id` stored in the header.
    pub fn id(self) -> u16 {
        match self {
            Self::XChaCha20Poly1305 => 1,
            Self::Aes256Gcm => 2,
        }
    }
    /// Name shown to users and accepted by the CLI `--algorithm` option.
    pub fn name(self) -> &'static str {
        match self {
            Self::XChaCha20Poly1305 => "xchacha20-poly1305",
            Self::Aes256Gcm => "aes-256-gcm",
        }
    }
}

/// The public 64-byte file header.
///
/// Layout (little-endian): magic[8], version u16, header length u16,
/// suite u16, reserved u16, Argon2 memory KiB u32, passes u32, lanes u32,
/// chunk size u32, salt[16], nonce prefix[16].
#[derive(Clone)]
pub struct Header {
    pub(crate) raw: [u8; 64],
    pub suite: Suite,
}
impl Header {
    /// Builds a header with the fixed v1 parameters and fresh random values.
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
        // v1 has exactly one valid set of fixed fields per suite: compare the
        // first 32 bytes with a freshly built header. This rejects attacker-
        // chosen KDF costs or chunk sizes before any memory is allocated.
        let expected = Self::new(suite, [0; 16], [0; 16]);
        if raw[..32] != expected.raw[..32] {
            return Err(Error::Format("버전/헤더/KDF/청크 설정"));
        }
        Ok(Self { raw, suite })
    }
    pub fn bytes(&self) -> &[u8; 64] {
        &self.raw
    }
    /// Argon2id / HKDF salt, random per file.
    pub(crate) fn salt(&self) -> &[u8] {
        &self.raw[32..48]
    }
    /// Random nonce prefix, combined with the record index to form each nonce.
    pub(crate) fn prefix(&self) -> &[u8] {
        &self.raw[48..64]
    }
}

/// The 13-byte header in front of every record: kind u8, index u64, length u32.
/// Kinds: 1 = META (filename), 2 = DATA (file bytes), 3 = FINAL (size, count, HMAC).
#[derive(Debug)]
pub struct RecordHeader {
    pub kind: u8,
    pub index: u64,
    pub len: usize,
}
impl RecordHeader {
    /// Parses and checks a record header against the index the reader expects
    /// next. Lengths are bounded per kind, so a forged header can never make
    /// the reader allocate an attacker-chosen amount of memory.
    pub fn parse(raw: [u8; 13], expected: u64) -> Result<Self> {
        let index = u64::from_le_bytes(raw[1..9].try_into().map_err(|_| Error::Authentication)?);
        let len =
            u32::from_le_bytes(raw[9..13].try_into().map_err(|_| Error::Authentication)?) as usize;
        let valid = match raw[0] {
            // META: always first; 2-byte name length + up to 4096 name bytes.
            1 => index == 0 && (2..=4098).contains(&len),
            // DATA: 1 byte up to one full chunk.
            2 => index > 0 && (1..=CHUNK_SIZE).contains(&len),
            // FINAL: size u64 + chunk count u64 + HMAC-SHA256 = 48 bytes.
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
/// Overflow-checked `+1` for record indexes and counters.
pub(crate) fn increment(value: u64) -> Result<u64> {
    value.checked_add(1).ok_or(Error::Authentication)
}

/// Accepts only a plain basename that is safe to create on Windows, macOS and
/// Linux: no separators, no path traversal, no control or reserved characters,
/// no trailing dot/space, and no Windows device names (CON, COM1, ...).
/// An empty name is allowed and means "no stored filename".
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
    // Windows treats "CON.txt" or "com1 .log" as the device itself, so check
    // the part before the first dot, ignoring trailing spaces and case.
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
        // Windows also maps superscript digits to COM/LPT devices.
        || ["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"].contains(&stem.as_str())
    {
        return Err(Error::Format("예약 파일명"));
    }
    Ok(())
}
