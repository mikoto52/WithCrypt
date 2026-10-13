//! Independent, read-only AxCrypt 1.x/2.x (file formats 3.x/4.0) implementation.
//! See docs/axx-v1.md and docs/axx-v2.md. Authenticate the complete ciphertext
//! before releasing metadata or plaintext. v1 supports ASCII passwords; v2
//! derives its keys from UTF-8 password bytes.
use crate::{Error, Observer, Result, Stage, format, notify};
use aes::{
    Aes128,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
};
use sha1::{Digest, Sha1};
use std::io::{self, Read, Seek, SeekFrom, Write};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const MAGIC: [u8; 16] = [
    0xc0, 0xb9, 0x07, 0x2e, 0x4f, 0x93, 0xf1, 0x46, 0xa0, 0x15, 0x79, 0x2c, 0xa1, 0xd9, 0xe8, 0x21,
];
const MAX_HEADER: usize = 1024 * 1024;
const MAX_ITERATIONS: u32 = 1_000_000;
#[derive(Debug, Clone)]
pub struct Summary {
    pub format_version: u8,
    pub filename: String,
    pub original_size: u64,
}
impl Summary {
    pub fn format_name(&self) -> &'static str {
        if self.format_version == 4 {
            "AxCrypt 2.x"
        } else {
            "AxCrypt 1.x"
        }
    }
}

/// Authenticated AxCrypt metadata and the selected format implementation.
pub struct Decryption {
    pub summary: Summary,
    state: Version,
}
enum Version {
    V1(V1Decryption),
    V2(super::axx_v2::Decryption),
}
impl Decryption {
    pub fn begin<R: Read + Seek>(
        reader: &mut R,
        password: &[u8],
        observer: &mut Observer<'_>,
    ) -> Result<Self> {
        let version = file_version(reader)?;
        let state = match version {
            3 => Version::V1(V1Decryption::begin(reader, password, observer)?),
            4 => Version::V2(super::axx_v2::Decryption::begin(
                reader, password, observer,
            )?),
            _ => return Err(Error::AxCryptFormat("지원하지 않는 AxCrypt 파일 버전")),
        };
        let summary = match &state {
            Version::V1(v) => v.summary.clone(),
            Version::V2(v) => v.summary.clone(),
        };
        Ok(Self { summary, state })
    }
    pub fn finish<R: Read + Seek, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        observer: &mut Observer<'_>,
    ) -> Result<Summary> {
        match &self.state {
            Version::V1(v) => v.finish(reader, writer, observer),
            Version::V2(v) => v.finish(reader, writer, observer),
        }
    }
}
/// Read only bounded header metadata to identify the version before key derivation.
pub fn file_version<R: Read + Seek>(reader: &mut R) -> Result<u8> {
    reader.seek(SeekFrom::Start(0))?;
    let mut magic = [0; 16];
    reader.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(bad());
    }
    let mut total = 16u64;
    for _ in 0..256 {
        let mut prefix = [0; 5];
        reader.read_exact(&mut prefix)?;
        let length = u32::from_le_bytes(prefix[..4].try_into().map_err(|_| bad())?) as u64;
        total = total.checked_add(length).ok_or_else(bad)?;
        if length < 5 || total > MAX_HEADER as u64 || prefix[4] == 63 {
            return Err(bad());
        }
        if prefix[4] == 3 {
            if length < 10 {
                return Err(bad());
            }
            let mut version = [0];
            reader.read_exact(&mut version)?;
            return Ok(version[0]);
        }
        reader.seek(SeekFrom::Current((length - 5) as i64))?;
    }
    Err(bad())
}
struct V1Decryption {
    pub summary: Summary,
    offset: u64,
    encrypted_len: u64,
    plain_len: u64,
    compressed: bool,
    key: Zeroizing<[u8; 16]>,
    iv: [u8; 16],
}
fn bad() -> Error {
    Error::AxCryptFormat("잘못되거나 지원하지 않는 헤더")
}
fn u64_at(v: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        v.get(offset..offset + 8)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?,
    ))
}
fn subkey(master: &[u8; 16], id: u8) -> Zeroizing<[u8; 16]> {
    let cipher = Aes128::new(master.into());
    let mut block = [0; 16];
    block[0] = id;
    cipher.encrypt_block((&mut block).into());
    Zeroizing::new(block)
}
fn cbc_header(key: &[u8; 16], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(bad());
    }
    let cipher = Aes128::new(key.into());
    let mut result = Zeroizing::new(data.to_vec());
    let mut previous = [0; 16];
    for block in result.as_chunks_mut::<16>().0 {
        let encrypted: [u8; 16] = *block;
        cipher.decrypt_block((&mut *block).into());
        for (byte, prev) in block.iter_mut().zip(previous) {
            *byte ^= prev;
        }
        previous = encrypted;
    }
    Ok(result)
}
fn unwrap(
    data: &[u8],
    password: &[u8],
    observer: &mut Observer<'_>,
) -> Result<Zeroizing<[u8; 16]>> {
    if data.len() != 44 {
        return Err(bad());
    }
    let rounds = u32::from_le_bytes(data[40..44].try_into().map_err(|_| bad())?);
    if rounds == 0 || rounds > MAX_ITERATIONS {
        return Err(Error::AxCryptFormat("키 래핑 반복 횟수 제한"));
    }
    let hash = Zeroizing::new(Sha1::digest(password).to_vec());
    let mut kek = Zeroizing::new([0; 16]);
    for i in 0..16 {
        kek[i] = hash[i] ^ data[24 + i];
    }
    let cipher = Aes128::new((&*kek).into());
    let mut wrap = Zeroizing::new([0; 24]);
    wrap.copy_from_slice(&data[..24]);
    for j in (0..rounds).rev() {
        if j % 1024 == 0 {
            notify(observer, Stage::Kdf, 0)?;
        }
        for i in (1..=2usize).rev() {
            let t = (2 * u64::from(j) + i as u64).to_le_bytes();
            let mut block = Zeroizing::new([0; 16]);
            for k in 0..8 {
                block[k] = wrap[k] ^ t[k];
            }
            block[8..].copy_from_slice(&wrap[i * 8..i * 8 + 8]);
            cipher.decrypt_block((&mut *block).into());
            wrap[..8].copy_from_slice(&block[..8]);
            wrap[i * 8..i * 8 + 8].copy_from_slice(&block[8..]);
        }
    }
    if !bool::from(wrap[..8].ct_eq(&[0xa6; 8])) {
        return Err(Error::Authentication);
    }
    let mut master = Zeroizing::new([0; 16]);
    master.copy_from_slice(&wrap[8..]);
    Ok(master)
}
impl V1Decryption {
    pub fn begin<R: Read + Seek>(
        reader: &mut R,
        password: &[u8],
        observer: &mut Observer<'_>,
    ) -> Result<Self> {
        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }
        if !password.is_ascii() {
            return Err(Error::AxCryptFormat(
                "현재는 ASCII 비밀번호만 지원합니다. 기존 AxCrypt의 Windows 코드 페이지 비밀번호는 후속 지원 예정입니다",
            ));
        }
        reader.seek(SeekFrom::Start(0))?;
        let mut magic = [0; 16];
        reader.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(bad());
        }
        let mut headers = Vec::new();
        let mut bytes = 16usize;
        let mut tag = [0; 16];
        loop {
            let mut prefix = [0; 5];
            reader.read_exact(&mut prefix)?;
            let len = u32::from_le_bytes(prefix[..4].try_into().map_err(|_| bad())?) as usize;
            bytes = bytes.checked_add(len).ok_or_else(bad)?;
            if len < 5 || bytes > MAX_HEADER || headers.len() >= 256 {
                return Err(bad());
            }
            let mut data = vec![0; len - 5];
            reader.read_exact(&mut data)?;
            if headers.is_empty() {
                if prefix[4] != 2 || data.len() != 16 {
                    return Err(bad());
                }
                tag.copy_from_slice(&data);
            } else if prefix[4] == 2 || headers.iter().any(|(t, _)| *t == prefix[4]) {
                return Err(bad());
            }
            let last = prefix[4] == 63;
            headers.push((prefix[4], data));
            if last {
                break;
            }
        }
        let get = |id| {
            headers
                .iter()
                .find(|(t, _)| *t == id)
                .map(|(_, v)| v.as_slice())
                .ok_or_else(bad)
        };
        let version = get(3)?;
        if version.len() < 5 || version[0] != 3 || version[1] > 2 {
            return Err(Error::AxCryptFormat("현재 파일 형식 3.0~3.2만 지원합니다"));
        }
        let encrypted_len = u64_at(get(63)?, 0)?;
        let offset = reader.stream_position()?;
        if encrypted_len == 0
            || !encrypted_len.is_multiple_of(16)
            || reader.seek(SeekFrom::End(0))?
                != offset.checked_add(encrypted_len).ok_or_else(bad)?
        {
            return Err(bad());
        }
        notify(observer, Stage::Kdf, 0)?;
        let master = unwrap(get(4)?, password, observer)?;
        // AxCrypt's historical HMAC uses 20-byte pads rather than SHA-1's
        // standard 64-byte pads. This is format compatibility, not new crypto.
        let mac_key = subkey(&master, 0);
        let mut inner_pad = Zeroizing::new([0x36; 20]);
        let mut outer_pad = Zeroizing::new([0x5c; 20]);
        for i in 0..16 {
            inner_pad[i] ^= mac_key[i];
            outer_pad[i] ^= mac_key[i];
        }
        let mut inner = Sha1::new();
        inner.update(inner_pad.as_slice());
        reader.seek(SeekFrom::Start(37))?;
        let mut buffer = [0; 65536];
        loop {
            let n = match reader.read(&mut buffer) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if n == 0 {
                break;
            }
            inner.update(&buffer[..n]);
            notify(observer, Stage::Verifying, 0)?;
        }
        let mut outer = Sha1::new();
        outer.update(outer_pad.as_slice());
        outer.update(inner.finalize());
        if !bool::from(outer.finalize()[..16].ct_eq(&tag)) {
            return Err(Error::Authentication);
        }
        let header_key = subkey(&master, 2);
        let info = cbc_header(&header_key, get(66)?)?;
        let plain_len = u64_at(&info, 0)?;
        if plain_len
            .checked_div(16)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(16))
            != Some(encrypted_len)
        {
            return Err(bad());
        }
        let iv = info
            .get(8..24)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?;
        let compressed = match get(69) {
            Ok(v) => {
                let v = cbc_header(&header_key, v)?;
                i32::from_le_bytes(v[..4].try_into().map_err(|_| bad())?) != 0
            }
            Err(_) => get(67).is_ok(),
        };
        let original_size = if compressed {
            u64_at(&cbc_header(&header_key, get(67)?)?, 0)?
        } else {
            plain_len
        };
        let filename = if let Ok(v) = get(70) {
            let v = cbc_header(&header_key, v)?;
            let mut units = Vec::new();
            let mut terminated = false;
            for pair in v.as_chunks::<2>().0 {
                let unit = u16::from_le_bytes([pair[0], pair[1]]);
                if unit == 0 {
                    terminated = true;
                    break;
                }
                units.push(unit);
            }
            if !terminated {
                return Err(bad());
            }
            String::from_utf16(&units).map_err(|_| bad())?
        } else {
            let v = cbc_header(&header_key, get(65)?)?;
            let end = v.iter().position(|b| *b == 0).ok_or_else(bad)?;
            if !v[..end].is_ascii() {
                return Err(Error::AxCryptFormat(
                    "비 ASCII 파일명에는 Unicode 헤더가 필요합니다",
                ));
            }
            String::from_utf8(v[..end].to_vec()).map_err(|_| bad())?
        };
        format::validate_filename(&filename)?;
        reader.seek(SeekFrom::Start(offset))?;
        Ok(Self {
            summary: Summary {
                format_version: 3,
                filename,
                original_size,
            },
            offset,
            encrypted_len,
            plain_len,
            compressed,
            key: subkey(&master, 3),
            iv,
        })
    }
    pub fn finish<R: Read + Seek, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        observer: &mut Observer<'_>,
    ) -> Result<Summary> {
        reader.seek(SeekFrom::Start(self.offset))?;
        let mut cbc = CbcReader {
            reader,
            cipher: Aes128::new((&*self.key).into()),
            previous: self.iv,
            remaining: self.encrypted_len,
            plaintext: self.plain_len,
            block: Zeroizing::new([0; 16]),
            position: 0,
            available: 0,
        };
        let mut total = 0u64;
        let mut buffer = Zeroizing::new([0; 65536]);
        if self.compressed {
            let mut zlib = flate2::read::ZlibDecoder::new(&mut cbc);
            copy_bounded(
                &mut zlib,
                writer,
                &mut buffer[..],
                &mut total,
                self.summary.original_size,
                observer,
            )?;
            if zlib.total_in() != self.plain_len {
                return Err(bad());
            }
        } else {
            copy_bounded(
                &mut cbc,
                writer,
                &mut buffer[..],
                &mut total,
                self.summary.original_size,
                observer,
            )?;
        }
        // Validate the encrypted PKCS#7 padding even when decompression stopped.
        let mut drain = [0; 16];
        while cbc.read(&mut drain)? != 0 {}
        if total != self.summary.original_size {
            return Err(Error::Authentication);
        }
        Ok(self.summary.clone())
    }
}
pub(super) fn copy_bounded<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut [u8],
    total: &mut u64,
    limit: u64,
    observer: &mut Observer<'_>,
) -> Result<()> {
    loop {
        let n = match reader.read(buffer) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            break;
        }
        *total = total.checked_add(n as u64).ok_or_else(bad)?;
        if *total > limit {
            return Err(bad());
        }
        writer.write_all(&buffer[..n])?;
        notify(observer, Stage::Processing, *total)?;
    }
    Ok(())
}
struct CbcReader<'a, R> {
    reader: &'a mut R,
    cipher: Aes128,
    previous: [u8; 16],
    remaining: u64,
    plaintext: u64,
    block: Zeroizing<[u8; 16]>,
    position: usize,
    available: usize,
}
impl<R: Read> Read for CbcReader<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < out.len() {
            if self.position == self.available {
                if self.remaining == 0 {
                    return Ok(written);
                }
                self.reader.read_exact(&mut *self.block)?;
                let encrypted = *self.block;
                self.cipher.decrypt_block((&mut *self.block).into());
                for i in 0..16 {
                    self.block[i] ^= self.previous[i];
                }
                self.previous = encrypted;
                self.remaining -= 16;
                self.available = self.plaintext.min(16) as usize;
                self.plaintext -= self.available as u64;
                self.position = 0;
                if self.remaining == 0 {
                    let pad = 16 - self.available;
                    if self.block[self.available..].iter().any(|v| *v != pad as u8) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid AxCrypt padding",
                        ));
                    }
                }
                if self.available == 0 {
                    return Ok(written);
                }
            }
            let n = (out.len() - written).min(self.available - self.position);
            out[written..written + n]
                .copy_from_slice(&self.block[self.position..self.position + n]);
            self.position += n;
            written += n;
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_is_batched() {
        struct Counter {
            bytes: Vec<u8>,
            calls: usize,
        }
        impl Write for Counter {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                self.bytes.extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let encrypted = include_bytes!("../../../tests/fixtures/axcrypt-v1/img1-jpg.axx");
        let original = include_bytes!("../../../tests/fixtures/axcrypt-v1/original/img1.jpg");
        let mut reader = io::Cursor::new(encrypted);
        let state = Decryption::begin(&mut reader, b"1111", &mut |_| true).unwrap();
        let mut writer = Counter {
            bytes: Vec::new(),
            calls: 0,
        };
        let mut updates = 0;
        state
            .finish(&mut reader, &mut writer, &mut |_| {
                updates += 1;
                true
            })
            .unwrap();
        assert_eq!(writer.bytes, original);
        let expected_calls = original.len().div_ceil(65536);
        assert_eq!(writer.calls, expected_calls);
        assert_eq!(updates, expected_calls);
        eprintln!(
            "{} bytes: {} writes, {} progress updates",
            original.len(),
            writer.calls,
            updates
        );
    }
    #[test]
    fn supplied_axcrypt_samples() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/axcrypt-v1");
        for item in std::fs::read_dir(&root).unwrap() {
            let path = item.unwrap().path();
            if path.extension().and_then(|v| v.to_str()) != Some("axx") {
                continue;
            }
            let mut reader = std::fs::File::open(&path).unwrap();
            let state = Decryption::begin(&mut reader, b"1111", &mut |_| true)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let mut result = Vec::new();
            state
                .finish(&mut reader, &mut result, &mut |_| true)
                .unwrap();
            assert_eq!(
                result,
                std::fs::read(root.join("original").join(&state.summary.filename)).unwrap(),
                "{}",
                path.display()
            );
        }
    }
    #[test]
    fn rejects_password_tampering_truncation_and_excessive_work() {
        let original = include_bytes!("../../../tests/fixtures/axcrypt-v1/Blank File-txt.axx");
        assert!(matches!(
            Decryption::begin(&mut io::Cursor::new(original), b"wrong", &mut |_| true),
            Err(Error::Authentication)
        ));
        for length in 0..original.len() {
            assert!(
                Decryption::begin(
                    &mut io::Cursor::new(&original[..length]),
                    b"1111",
                    &mut |_| true
                )
                .is_err()
            );
        }
        for index in [21, 40, 100, original.len() - 1] {
            let mut data = original.to_vec();
            data[index] ^= 1;
            assert!(Decryption::begin(&mut io::Cursor::new(data), b"1111", &mut |_| true).is_err());
        }
        let mut excessive = original.to_vec();
        excessive[256..260].fill(255);
        assert!(
            Decryption::begin(&mut io::Cursor::new(excessive), b"1111", &mut |_| true).is_err()
        );
        let mut trailing = original.to_vec();
        trailing.push(0);
        assert!(Decryption::begin(&mut io::Cursor::new(trailing), b"1111", &mut |_| true).is_err());
    }
    #[test]
    fn safe_file_transactions() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/axcrypt-v1");
        let input = root.join("Text File-txt.axx");
        let out = tempfile::tempdir().unwrap();
        let summary =
            crate::files::decrypt_axcrypt_into(&input, out.path(), b"1111", &mut |_| true).unwrap();
        let destination = out.path().join(&summary.filename);
        let before = std::fs::read(&destination).unwrap();
        assert!(matches!(
            crate::files::decrypt_axcrypt_into(&input, out.path(), b"1111", &mut |_| true),
            Err(Error::OutputExists)
        ));
        assert_eq!(std::fs::read(&destination).unwrap(), before);
        let empty = tempfile::tempdir().unwrap();
        assert!(
            crate::files::decrypt_axcrypt_into(&input, empty.path(), b"wrong", &mut |_| true)
                .is_err()
        );
        assert_eq!(std::fs::read_dir(empty.path()).unwrap().count(), 0);
        assert!(
            crate::files::decrypt_axcrypt_into(&input, empty.path(), b"1111", &mut |p| p.stage
                != Stage::Processing)
            .is_err()
        );
        assert_eq!(std::fs::read_dir(empty.path()).unwrap().count(), 0);
        assert!(matches!(
            crate::files::decrypt_axcrypt_into(&input, empty.path(), b"1111", &mut |p| {
                p.stage != Stage::Processing || p.bytes == 0
            }),
            Err(Error::Cancelled)
        ));
        assert_eq!(std::fs::read_dir(empty.path()).unwrap().count(), 0);
    }
}
