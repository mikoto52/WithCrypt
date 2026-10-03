//! Bounded pipe: generated input -> encrypt -> verify. No full-file allocation.
#![forbid(unsafe_code)]
use std::{
    io::{self, Read, Write},
    sync::mpsc,
    thread,
    time::Instant,
};
use withcrypt_core::{Suite, encrypt, verify};
struct Generated {
    remaining: u64,
}
impl Read for Generated {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.remaining.min(out.len() as u64) as usize;
        out[..n].fill(0xa5);
        self.remaining -= n as u64;
        Ok(n)
    }
}
struct PipeWriter(mpsc::SyncSender<Vec<u8>>);
impl Write for PipeWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0
            .send(b.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct PipeReader {
    rx: mpsc::Receiver<Vec<u8>>,
    current: io::Cursor<Vec<u8>>,
}
impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            let n = self.current.read(out)?;
            if n > 0 {
                return Ok(n);
            }
            match self.rx.recv() {
                Ok(v) => self.current = io::Cursor::new(v),
                Err(_) => return Ok(0),
            }
        }
    }
}
fn main() {
    let bytes = std::env::args()
        .nth(1)
        .map(|s| s.parse::<u64>().expect("byte count"))
        .unwrap_or(32 * 1024 * 1024);
    for suite in [Suite::XChaCha20Poly1305, Suite::Aes256Gcm] {
        let now = Instant::now();
        let (tx, rx) = mpsc::sync_channel(1);
        let producer = thread::spawn(move || {
            encrypt(
                &mut Generated { remaining: bytes },
                &mut PipeWriter(tx),
                b"public stress password",
                suite,
                "",
                &mut |_| true,
            )
        });
        let result = verify(
            &mut PipeReader {
                rx,
                current: io::Cursor::new(Vec::new()),
            },
            b"public stress password",
            &mut |_| true,
        )
        .expect("verify");
        producer.join().expect("producer").expect("encrypt");
        assert_eq!(result.original_size, bytes);
        println!(
            "{}: {} bytes, {:.3}s, {:.1} MiB/s (encrypt + verify)",
            suite.name(),
            bytes,
            now.elapsed().as_secs_f64(),
            bytes as f64 / 1048576.0 / now.elapsed().as_secs_f64()
        );
    }
}
