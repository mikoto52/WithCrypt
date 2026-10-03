use crate::{
    crypto::Keys,
    format::{RecordHeader, increment, validate_filename},
    *,
};
use hmac::Mac;
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

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
fn exact(reader: &mut impl Read, buffer: &mut [u8]) -> Result<()> {
    if fill(reader, buffer)? != buffer.len() {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn buffer(size: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut b = Vec::new();
    b.try_reserve_exact(size + 16)
        .map_err(|_| Error::Resource)?;
    b.resize(size, 0);
    Ok(Zeroizing::new(b))
}
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
    let mut meta = Zeroizing::new((filename.len() as u16).to_le_bytes().to_vec());
    meta.extend_from_slice(filename.as_bytes());
    write_record(w, &h, &keys, 1, 0, &mut meta)?;
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
pub fn decrypt(
    r: &mut impl Read,
    w: &mut impl Write,
    password: &[u8],
    observer: &mut Observer<'_>,
) -> Result<Summary> {
    let mut raw = [0; 64];
    exact(r, &mut raw)?;
    let h = Header::parse(raw)?;
    notify(observer, Stage::Kdf, 0)?;
    let mut keys = Keys::derive(password, &h)?;
    let mut expected = 0u64;
    let mut size = 0u64;
    let mut count = 0u64;
    let mut short = false;
    let mut filename = String::new();
    let mut data = buffer(CHUNK_SIZE)?;
    loop {
        notify(observer, Stage::Processing, size)?;
        let mut rh = [0; 13];
        exact(r, &mut rh)?;
        let record = RecordHeader::parse(rh, expected)?;
        if expected == 0 && record.kind != 1
            || expected > 0 && record.kind == 1
            || short && record.kind != 3
        {
            return Err(Error::Authentication);
        }
        data.resize(record.len + 16, 0);
        exact(r, &mut data)?;
        keys.crypt(&h, &rh, expected, &mut data, false)?;
        match record.kind {
            1 => {
                let len = u16::from_le_bytes([data[0], data[1]]) as usize;
                if len + 2 != data.len() {
                    return Err(Error::Authentication);
                }
                filename = std::str::from_utf8(&data[2..])
                    .map_err(|_| Error::Authentication)?
                    .to_owned();
                validate_filename(&filename).map_err(|_| Error::Authentication)?;
            }
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
                keys.mac
                    .verify_slice(&data[16..])
                    .map_err(|_| Error::Authentication)?;
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
pub fn verify(r: &mut impl Read, password: &[u8], observer: &mut Observer<'_>) -> Result<Summary> {
    decrypt(r, &mut io::sink(), password, observer)
}

#[cfg(test)]
mod tests;
