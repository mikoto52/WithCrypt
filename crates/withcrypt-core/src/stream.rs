//! Streaming encryption and decryption over any `Read`/`Write` pair.
//!
//! A file is `Header || META || DATA* || FINAL`. Data is processed one
//! 4 MiB chunk at a time, so memory use does not depend on the file size.
use crate::{
    crypto::Keys,
    format::{RecordHeader, increment, validate_filename},
    *,
};
use hmac::Mac;
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

/// Reads until `buffer` is full or EOF. A short `read` is not treated as EOF,
/// and `Interrupted` is retried. Returns the number of bytes read.
pub(crate) fn fill(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buffer.len() {
        match reader.read(&mut buffer[n..]) {
            Ok(0) => break,
            Ok(count) => n += count,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}
/// Like `fill`, but a truncated container is an authentication failure.
fn exact(reader: &mut impl Read, buffer: &mut [u8]) -> Result<()> {
    if fill(reader, buffer)? != buffer.len() {
        return Err(Error::Authentication);
    }
    Ok(())
}
/// A zeroized chunk buffer with room for the 16-byte AEAD tag, allocated
/// fallibly so a low-memory system reports an error instead of aborting.
fn buffer(size: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut b = Vec::new();
    b.try_reserve_exact(size + 16)
        .map_err(|_| Error::Resource)?;
    b.resize(size, 0);
    Ok(Zeroizing::new(b))
}
/// Encrypts `data` in place and writes `record header || ciphertext || tag`.
fn write_record(
    w: &mut impl Write,
    h: &Header,
    keys: &Keys,
    kind: u8,
    index: u64,
    data: &mut Vec<u8>,
) -> Result<()> {
    let raw = RecordHeader {
        kind,
        index,
        len: data.len(),
    }
    .bytes();
    keys.crypt(h, &raw, index, data, true)?;
    w.write_all(&raw)?;
    w.write_all(data)?;
    Ok(())
}
/// Encrypts `r` into `w` with a fresh random salt and nonce prefix, so the
/// same file and password never produce the same output twice.
/// `filename` is stored encrypted in META; pass "" to store no name.
pub fn encrypt(
    r: &mut impl Read,
    w: &mut impl Write,
    password: &[u8],
    suite: Suite,
    filename: &str,
    observer: &mut Observer<'_>,
) -> Result<Summary> {
    let mut salt = [0; 16];
    let mut prefix = [0; 16];
    getrandom::fill(&mut salt).map_err(|_| Error::Resource)?;
    getrandom::fill(&mut prefix).map_err(|_| Error::Resource)?;
    encrypt_header(
        r,
        w,
        password,
        Header::new(suite, salt, prefix),
        filename,
        observer,
    )
}
/// Encryption with a caller-supplied header; tests use it for fixed vectors.
pub(crate) fn encrypt_header(
    r: &mut impl Read,
    w: &mut impl Write,
    password: &[u8],
    h: Header,
    filename: &str,
    observer: &mut Observer<'_>,
) -> Result<Summary> {
    validate_filename(filename)?;
    notify(observer, Stage::Kdf, 0)?;
    let mut keys = Keys::derive(password, &h)?;
    notify(observer, Stage::Processing, 0)?;
    w.write_all(&h.raw)?;
    // META (index 0): u16 name length followed by the UTF-8 name.
    let mut meta = Zeroizing::new((filename.len() as u16).to_le_bytes().to_vec());
    meta.extend_from_slice(filename.as_bytes());
    write_record(w, &h, &keys, 1, 0, &mut meta)?;
    // DATA (index 1..): full chunks, then one short chunk at EOF. An empty
    // file has no DATA records, and an exact multiple adds no empty record.
    let mut data = buffer(CHUNK_SIZE)?;
    let mut size = 0u64;
    let mut count = 0u64;
    loop {
        notify(observer, Stage::Processing, size)?;
        data.resize(CHUNK_SIZE, 0);
        let n = fill(r, &mut data)?;
        if n == 0 {
            break;
        }
        data.truncate(n);
        keys.mac.update(&data);
        size = size.checked_add(n as u64).ok_or(Error::Authentication)?;
        count = increment(count)?;
        write_record(w, &h, &keys, 2, count, &mut data)?;
    }
    // FINAL: total size, DATA count and the plaintext HMAC. The reader checks
    // all three, which detects truncation and dropped or duplicated chunks.
    notify(observer, Stage::Verifying, size)?;
    let mut final_data = Zeroizing::new(Vec::with_capacity(64));
    final_data.extend_from_slice(&size.to_le_bytes());
    final_data.extend_from_slice(&count.to_le_bytes());
    final_data.extend_from_slice(&keys.mac.clone().finalize().into_bytes());
    write_record(w, &h, &keys, 3, increment(count)?, &mut final_data)?;
    Ok(Summary {
        suite: h.suite,
        original_size: size,
        data_chunks: count,
        filename: filename.to_owned(),
    })
}
/// Authenticated encrypted header. The body is NOT verified until finish succeeds.
///
/// Splitting decryption in two lets the GUI show the authenticated original
/// filename in its save dialog before any plaintext is written, while running
/// the expensive key derivation only once.
pub(crate) struct Decryption {
    h: Header,
    keys: Keys,
    pub(crate) filename: String,
}
impl Decryption {
    /// Reads the header, derives keys and authenticates META.
    /// A wrong password fails here, before any output exists.
    pub(crate) fn begin(
        r: &mut impl Read,
        password: &[u8],
        observer: &mut Observer<'_>,
    ) -> Result<Self> {
        let mut raw = [0; 64];
        exact(r, &mut raw)?;
        let h = Header::parse(raw)?;
        notify(observer, Stage::Kdf, 0)?;
        let keys = Keys::derive(password, &h)?;
        notify(observer, Stage::Processing, 0)?;
        let mut rh = [0; 13];
        exact(r, &mut rh)?;
        let record = RecordHeader::parse(rh, 0)?;
        if record.kind != 1 {
            return Err(Error::Authentication);
        }
        let mut data = buffer(record.len + 16)?;
        exact(r, &mut data)?;
        keys.crypt(&h, &rh, 0, &mut data, false)?;
        // The stored length must account for every decrypted byte.
        let len = u16::from_le_bytes([data[0], data[1]]) as usize;
        if len + 2 != data.len() {
            return Err(Error::Authentication);
        }
        let filename = std::str::from_utf8(&data[2..])
            .map_err(|_| Error::Authentication)?
            .to_owned();
        // Even an authenticated name is rejected if it could escape the
        // destination folder or is invalid on some platform.
        validate_filename(&filename).map_err(|_| Error::Authentication)?;
        notify(observer, Stage::Processing, 0)?;
        Ok(Self { h, keys, filename })
    }
    /// Decrypts DATA into `w` and verifies FINAL. Each chunk is written only
    /// after its own tag verifies, but the result as a whole (truncation,
    /// order, HMAC) is known to be valid only when this returns `Ok`.
    pub(crate) fn finish(
        self,
        r: &mut impl Read,
        w: &mut impl Write,
        observer: &mut Observer<'_>,
    ) -> Result<Summary> {
        let Self {
            h,
            mut keys,
            filename,
        } = self;
        let mut expected = 1u64;
        let mut size = 0u64;
        let mut count = 0u64;
        // Set after a short DATA record: only FINAL may follow it.
        let mut short = false;
        let mut data = buffer(CHUNK_SIZE)?;
        loop {
            notify(observer, Stage::Processing, size)?;
            let mut rh = [0; 13];
            exact(r, &mut rh)?;
            let record = RecordHeader::parse(rh, expected)?;
            if record.kind == 1 || short && record.kind != 3 {
                return Err(Error::Authentication);
            }
            data.resize(record.len + 16, 0);
            exact(r, &mut data)?;
            keys.crypt(&h, &rh, expected, &mut data, false)?;
            match record.kind {
                2 => {
                    size = size
                        .checked_add(data.len() as u64)
                        .ok_or(Error::Authentication)?;
                    count = increment(count)?;
                    keys.mac.update(&data);
                    w.write_all(&data)?;
                    short = data.len() < CHUNK_SIZE;
                }
                3 => {
                    notify(observer, Stage::Verifying, size)?;
                    if data[..8] != size.to_le_bytes() || data[8..16] != count.to_le_bytes() {
                        return Err(Error::Authentication);
                    }
                    // Constant-time comparison of the whole-file HMAC.
                    keys.mac
                        .verify_slice(&data[16..])
                        .map_err(|_| Error::Authentication)?;
                    // Nothing may follow FINAL.
                    let mut extra = [0; 1];
                    if fill(r, &mut extra)? != 0 {
                        return Err(Error::Authentication);
                    }
                    notify(observer, Stage::Verifying, size)?;
                    return Ok(Summary {
                        suite: h.suite,
                        original_size: size,
                        data_chunks: count,
                        filename,
                    });
                }
                _ => return Err(Error::Authentication),
            }
            expected = increment(expected)?;
        }
    }
}
/// Low-level decryption. `w` receives plaintext before the final check, so
/// callers must discard it on error; prefer the `files` API for real files.
pub fn decrypt(
    r: &mut impl Read,
    w: &mut impl Write,
    password: &[u8],
    observer: &mut Observer<'_>,
) -> Result<Summary> {
    Decryption::begin(r, password, observer)?.finish(r, w, observer)
}
/// Full authentication without writing plaintext anywhere.
pub fn verify(r: &mut impl Read, password: &[u8], observer: &mut Observer<'_>) -> Result<Summary> {
    decrypt(r, &mut io::sink(), password, observer)
}

#[cfg(test)]
mod tests;
