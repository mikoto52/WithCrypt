//! AxCrypt file format 4.0, independently implemented from its public specification.
use super::axx::{MAGIC, Summary};
use crate::{Error, Observer, Result, Stage, format, notify};
use aes::{
    Aes128, Aes256,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::io::{self, Read, Seek, SeekFrom, Write};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
const MAX_METADATA: usize = 1024 * 1024;
const MAX_WORK: u32 = 1_000_000;
fn bad() -> Error {
    Error::AxCryptFormat("잘못되거나 지원하지 않는 AxCrypt v2 형식")
}
fn number(v: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        v.get(offset..offset + 8)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?,
    ))
}
/// AES key size is identified by authenticated wrap/verifier checks, never by extension.
enum Cipher {
    A128(Box<Aes128>),
    A256(Box<Aes256>),
}
impl Cipher {
    fn new(key: &[u8]) -> Result<Self> {
        match key.len() {
            16 => Ok(Self::A128(Box::new(
                Aes128::new_from_slice(key).map_err(|_| bad())?,
            ))),
            32 => Ok(Self::A256(Box::new(
                Aes256::new_from_slice(key).map_err(|_| bad())?,
            ))),
            _ => Err(bad()),
        }
    }
    fn encrypt(&self, b: &mut [u8; 16]) {
        match self {
            Self::A128(c) => c.encrypt_block(b.into()),
            Self::A256(c) => c.encrypt_block(b.into()),
        }
    }
    fn decrypt(&self, b: &mut [u8; 16]) {
        match self {
            Self::A128(c) => c.decrypt_block(b.into()),
            Self::A256(c) => c.decrypt_block(b.into()),
        }
    }
}
struct Stream {
    cipher: Cipher,
    iv: [u8; 16],
    index: u64,
}
impl Stream {
    fn new(material: &[u8], size: usize, index: u64) -> Result<Self> {
        Ok(Self {
            cipher: Cipher::new(&material[..size])?,
            iv: material[size..size + 16].try_into().map_err(|_| bad())?,
            index,
        })
    }
    fn apply(&mut self, data: &mut [u8]) -> Result<()> {
        let mut done = 0;
        while done < data.len() {
            let offset = (self.index % 16) as usize;
            let n = (16 - offset).min(data.len() - done);
            let mut block = Zeroizing::new(self.iv);
            for (a, b) in block[8..].iter_mut().zip((self.index / 16).to_be_bytes()) {
                *a ^= b;
            }
            self.cipher.encrypt(&mut block);
            for (a, b) in data[done..done + n]
                .iter_mut()
                .zip(&block[offset..offset + n])
            {
                *a ^= b;
            }
            self.index = self.index.checked_add(n as u64).ok_or_else(bad)?;
            done += n;
        }
        Ok(())
    }
}
fn unwrap(
    data: &[u8],
    password: &[u8],
    size: usize,
    observer: &mut Observer<'_>,
) -> Result<Zeroizing<[u8; 128]>> {
    if data.len() != 248 {
        return Err(bad());
    }
    let rounds = u32::from_le_bytes(data[208..212].try_into().map_err(|_| bad())?);
    let derive_rounds = u32::from_le_bytes(data[244..248].try_into().map_err(|_| bad())?);
    if rounds == 0 || rounds > MAX_WORK || derive_rounds == 0 || derive_rounds > MAX_WORK {
        return Err(Error::AxCryptFormat("키 파생 반복 횟수 제한"));
    }
    notify(observer, Stage::Kdf, 0)?;
    let mut derived = Zeroizing::new([0; 64]);
    pbkdf2::pbkdf2_hmac::<Sha512>(password, &data[212..244], derive_rounds, &mut *derived);
    let mut key = Zeroizing::new(vec![0; size]);
    for i in 0..64 {
        key[i % size] ^= derived[i];
    }
    for i in 0..size {
        key[i] ^= data[144 + i];
    }
    let cipher = Cipher::new(&key)?;
    let n = (size + 16) / 8;
    let mut wrapped = Zeroizing::new([0; 136]);
    wrapped[..8 * (n + 1)].copy_from_slice(&data[..8 * (n + 1)]);
    for j in (0..rounds).rev() {
        if j % 1024 == 0 {
            notify(observer, Stage::Kdf, 0)?;
        }
        for i in (1..=n).rev() {
            let t = (n as u64 * u64::from(j) + i as u64).to_be_bytes();
            let mut b = Zeroizing::new([0; 16]);
            for k in 0..8 {
                b[k] = wrapped[k] ^ t[k];
            }
            b[8..].copy_from_slice(&wrapped[i * 8..i * 8 + 8]);
            cipher.decrypt(&mut b);
            wrapped[..8].copy_from_slice(&b[..8]);
            wrapped[i * 8..i * 8 + 8].copy_from_slice(&b[8..]);
        }
    }
    if !bool::from(wrapped[..8].ct_eq(&[0xa6; 8])) {
        return Err(Error::Authentication);
    }
    let mut material = Zeroizing::new([0; 128]);
    material.copy_from_slice(&wrapped[8..]);
    Ok(material)
}
pub(super) struct Decryption {
    pub summary: Summary,
    material: Zeroizing<[u8; 128]>,
    size: usize,
    data_offset: u64,
    data_end: u64,
    encrypted_len: u64,
    compressed: bool,
}
impl Decryption {
    pub fn begin<R: Read + Seek>(
        reader: &mut R,
        password: &[u8],
        observer: &mut Observer<'_>,
    ) -> Result<Self> {
        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }
        reader.seek(SeekFrom::Start(0))?;
        let length = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let mut magic = [0; 16];
        reader.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(bad());
        }
        let mut headers = Vec::new();
        let mut trailers = Vec::new();
        let mut metadata = 0usize;
        let mut end_headers = false;
        let mut end_data = false;
        let mut data_offset = 0;
        let mut data_end = 0;
        let mut encrypted_len = 0u64;
        let mac_offset;
        let mut tag = [0; 64];
        loop {
            let offset = reader.stream_position()?;
            let mut prefix = [0; 5];
            reader.read_exact(&mut prefix)?;
            let block_len = u32::from_le_bytes(prefix[..4].try_into().map_err(|_| bad())?) as u64;
            let kind = prefix[4];
            let end = offset.checked_add(block_len).ok_or_else(bad)?;
            if block_len < 5 || end > length {
                return Err(bad());
            }
            if kind == 20 {
                if !end_headers || end_data || block_len == 5 {
                    return Err(bad());
                }
                encrypted_len = encrypted_len.checked_add(block_len - 5).ok_or_else(bad)?;
                reader.seek(SeekFrom::Start(end))?;
                continue;
            }
            metadata = metadata.checked_add(block_len as usize).ok_or_else(bad)?;
            if metadata > MAX_METADATA || headers.len() + trailers.len() > 256 {
                return Err(bad());
            }
            let mut data = vec![0; (block_len - 5) as usize];
            reader.read_exact(&mut data)?;
            if headers.is_empty() {
                if kind != 2 || data != [0; 16] {
                    return Err(bad());
                }
            } else if kind == 2 {
                return Err(bad());
            }
            if !end_headers {
                if kind == 63 {
                    if data != [0; 8] {
                        return Err(bad());
                    }
                    end_headers = true;
                    data_offset = end;
                    continue;
                }
                if matches!(kind, 11 | 101) {
                    return Err(bad());
                }
                headers.push((kind, data));
            } else {
                if !end_data {
                    end_data = true;
                    data_end = offset;
                }
                if kind == 11 {
                    if data.len() != 64 || end != length {
                        return Err(bad());
                    }
                    tag.copy_from_slice(&data);
                    mac_offset = offset;
                    break;
                }
                if kind == 63 {
                    return Err(bad());
                }
                trailers.push((kind, data));
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
        if version.len() < 5 || version[..2] != [4, 0] {
            return Err(bad());
        }
        // Repeated singleton metadata must match exactly; key slots may repeat.
        for id in [3, 68, 69, 70, 102, 103] {
            let h: Vec<_> = headers.iter().filter(|(t, _)| *t == id).collect();
            let t: Vec<_> = trailers.iter().filter(|(t, _)| *t == id).collect();
            if h.len() > 1 || t.len() > 1 || h != t {
                return Err(bad());
            }
        }
        let wraps: Vec<_> = headers.iter().filter(|(t, _)| *t == 13).collect();
        if wraps.is_empty() || wraps.len() > 8 {
            return Err(Error::AxCryptFormat(
                "비밀번호 키 슬롯이 없거나 너무 많습니다",
            ));
        }
        if wraps
            != trailers
                .iter()
                .filter(|(t, _)| *t == 13)
                .collect::<Vec<_>>()
        {
            return Err(bad());
        }
        let mut matched = None;
        'slots: for (_, wrap) in &wraps {
            for size in [32, 16] {
                match unwrap(wrap, password, size, observer) {
                    Ok(material) => {
                        matched = Some((material, size));
                        break 'slots;
                    }
                    Err(Error::Authentication) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        let (material, size) = matched.ok_or(Error::Authentication)?;
        let mut mac_key = Zeroizing::new([0; 64]);
        Stream::new(&*material, size, 0)?.apply(&mut *mac_key)?;
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&*mac_key).map_err(|_| bad())?;
        reader.seek(SeekFrom::Start(0))?;
        let mut remaining = mac_offset;
        let mut buffer = [0; 65536];
        while remaining > 0 {
            let n = remaining.min(buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..n])?;
            mac.update(&buffer[..n]);
            remaining -= n as u64;
            notify(observer, Stage::Verifying, 0)?;
        }
        mac.verify_slice(&tag).map_err(|_| Error::Authentication)?;
        let decode = |data: &[u8], index: u64| -> Result<Zeroizing<Vec<u8>>> {
            let mut v = Zeroizing::new(data.to_vec());
            Stream::new(&*material, size, index)?.apply(&mut v)?;
            Ok(v)
        };
        let verifier = decode(get(103)?, 4096)?;
        if verifier.len() != 32
            || !(bool::from(verifier[..16].ct_eq(&verifier[16..]))
                || verifier[..16]
                    .iter()
                    .zip(&verifier[16..])
                    .all(|(a, b)| a ^ b == 255))
        {
            return Err(Error::Authentication);
        }
        let compression = decode(get(69)?, 512)?;
        if compression.len() != 1 {
            return Err(bad());
        }
        let compressed = compression[0] != 0;
        let filename_data = decode(get(70)?, 768)?;
        // Current generators use NUL-terminated UTF-8 with random padding.
        let end = filename_data.iter().position(|b| *b == 0).ok_or_else(bad)?;
        if end > 4096 {
            return Err(bad());
        }
        let filename = std::str::from_utf8(&filename_data[..end])
            .map_err(|_| bad())?
            .to_owned();
        format::validate_filename(&filename)?;
        let sizes: Vec<_> = trailers.iter().filter(|(t, _)| *t == 101).collect();
        if sizes.len() != 1 {
            return Err(bad());
        }
        let sizes = decode(&sizes[0].1, 2048)?;
        if sizes.len() != 16 {
            return Err(bad());
        }
        let original_size = number(&sizes, 0)?;
        if number(&sizes, 8)? != encrypted_len || (!compressed && original_size != encrypted_len) {
            return Err(bad());
        }
        Ok(Self {
            summary: Summary {
                format_version: 4,
                filename,
                original_size,
            },
            material,
            size,
            data_offset,
            data_end,
            encrypted_len,
            compressed,
        })
    }
    pub fn finish<R: Read + Seek, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        observer: &mut Observer<'_>,
    ) -> Result<Summary> {
        reader.seek(SeekFrom::Start(self.data_offset))?;
        let mut data = DataReader {
            reader,
            stream: Stream::new(&*self.material, self.size, 1048576)?,
            remaining: 0,
            total: self.encrypted_len,
        };
        let mut total = 0;
        let mut buffer = Zeroizing::new([0; 65536]);
        if self.compressed && self.encrypted_len > 0 {
            let mut zlib = flate2::read::ZlibDecoder::new(&mut data);
            super::axx::copy_bounded(
                &mut zlib,
                writer,
                &mut buffer[..],
                &mut total,
                self.summary.original_size,
                observer,
            )?;
            if zlib.total_in() != self.encrypted_len {
                return Err(bad());
            }
        } else {
            super::axx::copy_bounded(
                &mut data,
                writer,
                &mut buffer[..],
                &mut total,
                self.summary.original_size,
                observer,
            )?;
        }
        if total != self.summary.original_size
            || data.total != 0
            || data.remaining != 0
            || data.reader.stream_position()? != self.data_end
        {
            return Err(bad());
        }
        Ok(self.summary.clone())
    }
}
struct DataReader<'a, R> {
    reader: &'a mut R,
    stream: Stream,
    remaining: u64,
    total: u64,
}
impl<R: Read> Read for DataReader<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.total == 0 {
            return Ok(0);
        }
        let mut written = 0;
        while written < out.len() && self.total > 0 {
            if self.remaining == 0 {
                let mut prefix = [0; 5];
                self.reader.read_exact(&mut prefix)?;
                let n = u32::from_le_bytes(
                    prefix[..4]
                        .try_into()
                        .map_err(|_| io::ErrorKind::InvalidData)?,
                ) as u64;
                if prefix[4] != 20 || n <= 5 || n - 5 > self.total {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.remaining = n - 5;
            }
            let n = self.remaining.min((out.len() - written) as u64) as usize;
            self.reader.read_exact(&mut out[written..written + n])?;
            self.remaining -= n as u64;
            self.total -= n as u64;
            written += n;
        }
        self.stream
            .apply(&mut out[..written])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(written)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn xecrets_samples() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        for entry in std::fs::read_dir(root.join("axcrypt-v2")).unwrap() {
            let path = entry.unwrap().path();
            let mut reader = std::fs::File::open(&path).unwrap();
            let state = Decryption::begin(&mut reader, b"1111", &mut |_| true)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let mut output = Vec::new();
            state
                .finish(&mut reader, &mut output, &mut |_| true)
                .unwrap();
            assert_eq!(
                output,
                std::fs::read(
                    root.join("axcrypt-v1/original")
                        .join(state.summary.filename)
                )
                .unwrap()
            );
        }
    }
    fn resign(data: &mut [u8], state: &Decryption) {
        let offset = data.len() - 69;
        let mut key = Zeroizing::new([0; 64]);
        Stream::new(&*state.material, state.size, 0)
            .unwrap()
            .apply(&mut *key)
            .unwrap();
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&*key).unwrap();
        mac.update(&data[..offset]);
        data[offset + 5..].copy_from_slice(&mac.finalize().into_bytes());
    }
    fn rewrite_header(data: &mut [u8], state: &Decryption, kind: u8, index: u64, plaintext: &[u8]) {
        let mut offset = 16;
        while offset < data.len() {
            let len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            if data[offset + 4] == kind {
                let mut encoded = Zeroizing::new(vec![0; len - 5]);
                encoded[..plaintext.len()].copy_from_slice(plaintext);
                Stream::new(&*state.material, state.size, index)
                    .unwrap()
                    .apply(&mut encoded)
                    .unwrap();
                data[offset + 5..offset + len].copy_from_slice(&encoded);
            }
            offset += len;
        }
        resign(data, state);
    }
    #[test]
    fn rejects_corruption_truncation_and_hostile_metadata() {
        let sample = include_bytes!("../../../tests/fixtures/axcrypt-v2/Text File 2.txt.axx");
        assert!(matches!(
            Decryption::begin(&mut io::Cursor::new(sample), b"wrong", &mut |_| true),
            Err(Error::Authentication)
        ));
        for end in 0..sample.len() {
            assert!(
                Decryption::begin(&mut io::Cursor::new(&sample[..end]), b"1111", &mut |_| true)
                    .is_err()
            );
        }
        for index in [0, 598, 920, sample.len() - 1] {
            let mut data = sample.to_vec();
            data[index] ^= 1;
            assert!(Decryption::begin(&mut io::Cursor::new(data), b"1111", &mut |_| true).is_err());
        }
        let state =
            Decryption::begin(&mut io::Cursor::new(sample), b"1111", &mut |_| true).unwrap();
        let mut unsafe_name = sample.to_vec();
        rewrite_header(&mut unsafe_name, &state, 70, 768, b"../escape.txt\0");
        assert!(
            Decryption::begin(&mut io::Cursor::new(unsafe_name), b"1111", &mut |_| true).is_err()
        );
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("bad.axx");
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let mut wrong_size = sample.to_vec();
        let mut sizes = [0; 16];
        sizes[..8].copy_from_slice(&(state.summary.original_size + 1).to_le_bytes());
        sizes[8..].copy_from_slice(&state.encrypted_len.to_le_bytes());
        rewrite_header(&mut wrong_size, &state, 101, 2048, &sizes);
        std::fs::write(&input, &wrong_size).unwrap();
        assert!(crate::files::decrypt_axcrypt_into(&input, &out, b"1111", &mut |_| true).is_err());
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
        let mut excess = sample.to_vec();
        excess[47 + 5 + 208..47 + 5 + 212].fill(255);
        assert!(Decryption::begin(&mut io::Cursor::new(excess), b"1111", &mut |_| true).is_err());
        let mut trailing = sample.to_vec();
        trailing.push(0);
        assert!(Decryption::begin(&mut io::Cursor::new(trailing), b"1111", &mut |_| true).is_err());
        assert!(matches!(
            Decryption::begin(&mut io::Cursor::new(sample), b"1111", &mut |_| false),
            Err(Error::Cancelled)
        ));
    }
    #[test]
    fn file_transactions_and_partial_stream_reads() {
        let input = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/axcrypt-v2/img1.jpg.axx");
        let out = tempfile::tempdir().unwrap();
        let summary =
            crate::files::decrypt_axcrypt_into(&input, out.path(), b"1111", &mut |_| true).unwrap();
        assert!(matches!(
            crate::files::decrypt_axcrypt_into(&input, out.path(), b"1111", &mut |_| true),
            Err(Error::OutputExists)
        ));
        let cancelled = tempfile::tempdir().unwrap();
        assert!(matches!(
            crate::files::decrypt_axcrypt_into(&input, cancelled.path(), b"1111", &mut |p| p.stage
                != Stage::Processing
                || p.bytes == 0),
            Err(Error::Cancelled)
        ));
        assert_eq!(std::fs::read_dir(cancelled.path()).unwrap().count(), 0);
        let bytes = std::fs::read(&input).unwrap();
        let mut reader = io::Cursor::new(bytes);
        let state = Decryption::begin(&mut reader, b"1111", &mut |_| true).unwrap();
        reader.seek(SeekFrom::Start(state.data_offset)).unwrap();
        let mut data = DataReader {
            reader: &mut reader,
            stream: Stream::new(&*state.material, state.size, 1048576).unwrap(),
            remaining: 0,
            total: state.encrypted_len,
        };
        let mut small = [0; 7];
        let mut decoded = Vec::new();
        loop {
            let n = data.read(&mut small).unwrap();
            if n == 0 {
                break;
            }
            decoded.extend_from_slice(&small[..n]);
        }
        let actual = if state.compressed {
            let mut v = Vec::new();
            flate2::read::ZlibDecoder::new(decoded.as_slice())
                .read_to_end(&mut v)
                .unwrap();
            v
        } else {
            decoded
        };
        assert_eq!(
            actual,
            std::fs::read(out.path().join(summary.filename)).unwrap()
        );
    }
}
