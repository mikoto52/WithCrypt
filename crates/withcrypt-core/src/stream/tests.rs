use super::*;
use std::io::Cursor;
const PASSWORD: &[u8] = "  한글 비밀번호 🔒 e\u{301}  ".as_bytes();
const SUITES: [Suite; 2] = [Suite::XChaCha20Poly1305, Suite::Aes256Gcm];
fn fixed(suite: Suite, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt_header(
        &mut Cursor::new(input),
        &mut out,
        PASSWORD,
        Header::new(suite, [0x11; 16], [0x22; 16]),
        "test.bin",
        &mut |_| true,
    )
    .unwrap();
    out
}
fn rejects(bytes: &[u8]) {
    assert!(
        decrypt(
            &mut Cursor::new(bytes),
            &mut io::sink(),
            PASSWORD,
            &mut |_| true
        )
        .is_err()
    );
}
fn records(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    let mut pos = 64;
    while pos < bytes.len() {
        let len = u32::from_le_bytes(bytes[pos + 9..pos + 13].try_into().unwrap()) as usize + 29;
        result.push(bytes[pos..pos + len].to_vec());
        pos += len;
    }
    result
}
#[test]
fn roundtrips_boundaries_both_suites() {
    for suite in SUITES {
        for len in [
            0,
            1,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            CHUNK_SIZE * 2 + 357,
        ] {
            let input: Vec<u8> = (0..len).map(|n| n as u8).collect();
            let encrypted = fixed(suite, &input);
            let mut output = Vec::new();
            let result = decrypt(
                &mut Cursor::new(&encrypted),
                &mut output,
                PASSWORD,
                &mut |_| true,
            )
            .unwrap();
            assert_eq!(input, output);
            assert_eq!(result.original_size, len as u64);
            assert_eq!(result.suite, suite);
            assert_eq!(result.data_chunks, len.div_ceil(CHUNK_SIZE) as u64);
        }
    }
}
#[test]
fn password_randomness_and_early_authentication() {
    for suite in SUITES {
        let input = b"original bytes";
        let a = fixed(suite, input);
        let mut b = Vec::new();
        let mut c = Vec::new();
        encrypt(
            &mut Cursor::new(input),
            &mut b,
            PASSWORD,
            suite,
            "",
            &mut |_| true,
        )
        .unwrap();
        encrypt(
            &mut Cursor::new(input),
            &mut c,
            PASSWORD,
            suite,
            "",
            &mut |_| true,
        )
        .unwrap();
        assert_ne!(&b[32..48], &c[32..48]);
        assert_ne!(&b[48..64], &c[48..64]);
        assert_ne!(b, c);
        let mut output = Vec::new();
        assert!(matches!(
            decrypt(&mut Cursor::new(a), &mut output, b"wrong", &mut |_| true),
            Err(Error::Authentication)
        ));
        assert!(output.is_empty());
        assert!(matches!(
            encrypt(
                &mut Cursor::new(input),
                &mut Vec::new(),
                b"",
                suite,
                "",
                &mut |_| true
            ),
            Err(Error::EmptyPassword)
        ));
    }
}
#[test]
fn structural_and_authenticated_tampering() {
    for suite in SUITES {
        let original = fixed(suite, b"payload");
        for offset in [
            0,
            8,
            10,
            12,
            14,
            16,
            20,
            24,
            28,
            32,
            48,
            64,
            65,
            73,
            77,
            86,
            original.len() - 1,
        ] {
            let mut changed = original.clone();
            changed[offset] ^= 1;
            rejects(&changed);
        }
        let mut switched = original.clone();
        switched[12] = if suite.id() == 1 { 2 } else { 1 };
        rejects(&switched);
        for n in [0, 1, 63, 64, 65, 76, 77, original.len() - 1] {
            rejects(&original[..n]);
        }
        let mut trailing = original.clone();
        trailing.push(0);
        rejects(&trailing);
        let r = records(&original);
        for order in [
            vec![0, 2],
            vec![0, 1, 1, 2],
            vec![1, 0, 2],
            vec![0, 1],
            vec![0, 2, 1],
            vec![0, 0, 1, 2],
        ] {
            let mut changed = original[..64].to_vec();
            for i in order {
                changed.extend_from_slice(&r[i]);
            }
            rejects(&changed);
        }
        let mut foreign = Vec::new();
        encrypt(
            &mut Cursor::new(b"payload"),
            &mut foreign,
            PASSWORD,
            suite,
            "test.bin",
            &mut |_| true,
        )
        .unwrap();
        let mut changed = original[..64].to_vec();
        changed.extend_from_slice(&r[0]);
        changed.extend_from_slice(&records(&foreign)[1]);
        changed.extend_from_slice(&r[2]);
        rejects(&changed);
    }
}
#[test]
fn authenticated_invalid_final_and_short_chunk_sequence() {
    for suite in SUITES {
        let original = fixed(suite, b"payload");
        let h = Header::parse(original[..64].try_into().unwrap()).unwrap();
        let keys = Keys::derive(PASSWORD, &h).unwrap();
        let r = records(&original);
        for field in [0, 8, 16] {
            let mut final_record = r[2].clone();
            let rh: [u8; 13] = final_record[..13].try_into().unwrap();
            let mut plain = final_record[13..].to_vec();
            keys.crypt(&h, &rh, 2, &mut plain, false).unwrap();
            plain[field] ^= 1;
            keys.crypt(&h, &rh, 2, &mut plain, true).unwrap();
            final_record.truncate(13);
            final_record.extend(plain);
            let mut changed = original[..64].to_vec();
            changed.extend(&r[0]);
            changed.extend(&r[1]);
            changed.extend(final_record);
            rejects(&changed);
        }
        let mut changed = original[..64].to_vec();
        changed.extend(&r[0]);
        changed.extend(&r[1]);
        write_record(&mut changed, &h, &keys, 2, 2, &mut b"x".to_vec()).unwrap();
        rejects(&changed);
    }
}
#[test]
fn bounded_parser_and_overflow() {
    assert!(increment(u64::MAX).is_err());
    for kind in 0..=255 {
        for len in [0, 1, 2, 48, 4098, 4099, CHUNK_SIZE as u32, u32::MAX] {
            let mut raw = [0; 13];
            raw[0] = kind;
            raw[9..].copy_from_slice(&len.to_le_bytes());
            let _ = RecordHeader::parse(raw, 0);
        }
    }
    for name in [
        "../x", "/tmp/x", "a\\b", "CON", "nul.txt", "LPT1", "name:", "..", "a\0b",
    ] {
        assert!(validate_filename(name).is_err());
    }
}

#[test]
fn malformed_header_never_reaches_kdf() {
    for suite in SUITES {
        let header = Header::new(suite, [0; 16], [0; 16]);
        for i in 0..32 {
            let mut raw = *header.bytes();
            raw[i] ^= 0x80;
            let mut calls = 0;
            assert!(
                decrypt(
                    &mut Cursor::new(raw),
                    &mut io::sink(),
                    PASSWORD,
                    &mut |_| {
                        calls += 1;
                        true
                    }
                )
                .is_err()
            );
            assert_eq!(calls, 0);
        }
    }
}

#[test]
fn corrupt_final_never_publishes_and_commit_is_final() {
    use crate::files::{Operation, run};
    use std::fs;
    for suite in SUITES {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("source.esb");
        let output = dir.path().join("output");
        let good = fixed(suite, b"authenticated plaintext before final");
        let mut corrupt = good.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(&input, corrupt).unwrap();
        assert!(matches!(
            run(
                &input,
                Some(&output),
                PASSWORD,
                Operation::Decrypt,
                &mut |_| true
            ),
            Err(Error::Authentication)
        ));
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        fs::write(&input, good).unwrap();
        run(
            &input,
            Some(&output),
            PASSWORD,
            Operation::Decrypt,
            &mut |p| p.stage != Stage::Complete,
        )
        .unwrap();
        assert!(output.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o077,
                0
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn symlink_and_permission_protection() {
    use crate::files::{Operation, run};
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let output = dir.path().join("output");
    fs::write(&input, b"original").unwrap();
    symlink(&input, &output).unwrap();
    assert!(matches!(
        run(
            &input,
            Some(&output),
            PASSWORD,
            Operation::Encrypt(Suite::default()),
            &mut |_| true
        ),
        Err(Error::OutputExists)
    ));
    assert_eq!(fs::read(&input).unwrap(), b"original");
    let locked = dir.path().join("locked");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
    let result = run(
        &input,
        Some(&locked.join("out")),
        PASSWORD,
        Operation::Encrypt(Suite::default()),
        &mut |_| true,
    );
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
}
struct ShortReader {
    data: Cursor<Vec<u8>>,
    interrupt: bool,
}
impl Read for ShortReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let len = out.len().min(97);
        self.data.read(&mut out[..len])
    }
}
struct ShortWriter(Vec<u8>);
impl Write for ShortWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = b.len().min(71);
        self.0.extend_from_slice(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct BrokenWriter;
impl Write for BrokenWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("disk full"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn short_io_failure_and_cancellation() {
    for suite in SUITES {
        let input = vec![42; 8193];
        let mut reader = ShortReader {
            data: Cursor::new(input.clone()),
            interrupt: false,
        };
        let mut writer = ShortWriter(Vec::new());
        encrypt(&mut reader, &mut writer, PASSWORD, suite, "", &mut |_| true).unwrap();
        let mut reader = ShortReader {
            data: Cursor::new(writer.0),
            interrupt: false,
        };
        let mut writer = ShortWriter(Vec::new());
        decrypt(&mut reader, &mut writer, PASSWORD, &mut |_| true).unwrap();
        assert_eq!(writer.0, input);
        assert!(matches!(
            encrypt(
                &mut Cursor::new(&input),
                &mut BrokenWriter,
                PASSWORD,
                suite,
                "",
                &mut |_| true
            ),
            Err(Error::Io(_))
        ));
        let encrypted = fixed(suite, &input);
        assert!(matches!(
            decrypt(
                &mut Cursor::new(encrypted),
                &mut Vec::new(),
                PASSWORD,
                &mut |p| p.stage != Stage::Verifying
            ),
            Err(Error::Cancelled)
        ));
    }
}
#[test]
fn key_separation_hmac_and_vectors() {
    for suite in SUITES {
        let h = Header::new(suite, [0x11; 16], [0x22; 16]);
        let keys = Keys::derive(PASSWORD, &h).unwrap();
        assert_ne!(*keys.aes_key(&h, 0).unwrap(), *keys.aes_key(&h, 1).unwrap());
        assert_ne!(
            *keys.aes_key(&h, u64::MAX).unwrap(),
            *keys.aes_key(&h, u64::MAX - 1).unwrap()
        );
        let input = b"WithCrypt vector\x00\xff";
        let encrypted = fixed(suite, input);
        let r = records(&encrypted);
        let rh = r[2][..13].try_into().unwrap();
        let mut final_data = r[2][13..].to_vec();
        keys.crypt(&h, &rh, 2, &mut final_data, false).unwrap();
        let mut independent = keys.mac.clone();
        independent.update(input);
        independent.verify_slice(&final_data[16..]).unwrap();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../tests/fixtures/suite-{}.hex", suite.id()));
        if std::env::var_os("WITHCRYPT_UPDATE_VECTORS").is_some() {
            std::fs::write(&fixture, hex::encode(&encrypted)).unwrap();
        }
        let expected = std::fs::read_to_string(fixture).expect("checked-in vector");
        assert_eq!(hex::encode(encrypted), expected.trim());
    }
}

#[test]
fn file_transactions() {
    use crate::files::{Operation, run};
    use std::fs;
    for suite in SUITES {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        let enc = dir.path().join("out.esb");
        let out = dir.path().join("restored");
        fs::write(&input, b"keep me").unwrap();
        assert!(matches!(
            run(
                &input,
                Some(&input),
                PASSWORD,
                Operation::Encrypt(suite),
                &mut |_| true
            ),
            Err(Error::OutputExists)
        ));
        let alias = dir.path().join("alias");
        fs::hard_link(&input, &alias).unwrap();
        assert!(
            run(
                &input,
                Some(&alias),
                PASSWORD,
                Operation::Encrypt(suite),
                &mut |_| true
            )
            .is_err()
        );
        run(
            &input,
            Some(&enc),
            PASSWORD,
            Operation::Encrypt(suite),
            &mut |_| true,
        )
        .unwrap();
        assert!(
            run(&enc, Some(&out), b"wrong", Operation::Decrypt, &mut |_| {
                true
            })
            .is_err()
        );
        assert!(!out.exists());
        assert!(
            run(&enc, Some(&out), PASSWORD, Operation::Decrypt, &mut |p| p
                .stage
                != Stage::Committing)
            .is_err()
        );
        assert!(!out.exists());
        run(&enc, None, PASSWORD, Operation::Verify, &mut |_| true).unwrap();
        run(&enc, Some(&out), PASSWORD, Operation::Decrypt, &mut |_| {
            true
        })
        .unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"keep me");
        assert_eq!(fs::read(&input).unwrap(), b"keep me");
        fs::write(&out, b"competitor").unwrap();
        assert!(matches!(
            run(&enc, Some(&out), PASSWORD, Operation::Decrypt, &mut |_| {
                true
            }),
            Err(Error::OutputExists)
        ));
        assert_eq!(fs::read(&out).unwrap(), b"competitor");
        fs::remove_file(&out).unwrap();
        // A destination replaced mid-operation is reported and never deleted.
        assert!(matches!(
            run(&enc, Some(&out), PASSWORD, Operation::Decrypt, &mut |p| {
                if p.stage == Stage::Committing {
                    fs::remove_file(&out).unwrap();
                    fs::write(&out, b"competitor").unwrap();
                }
                true
            }),
            Err(Error::OutputChanged)
        ));
        assert_eq!(fs::read(&out).unwrap(), b"competitor");
        fs::remove_file(&out).unwrap();
        // Cancelling while writing removes the partial output in place.
        assert!(matches!(
            run(&enc, Some(&out), PASSWORD, Operation::Decrypt, &mut |p| p
                .stage
                != Stage::Verifying),
            Err(Error::Cancelled)
        ));
        assert!(!out.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
        assert!(matches!(
            run(
                &input,
                Some(&out),
                PASSWORD,
                Operation::Encrypt(suite),
                &mut |p| {
                    if p.stage == Stage::Verifying {
                        fs::write(&input, b"changed size").unwrap();
                    }
                    true
                }
            ),
            Err(Error::InputChanged)
        ));
        assert!(!out.exists());
    }
}

#[test]
fn filename_restore_and_prepared_transaction() {
    use crate::files::{self, Operation};
    use std::{fs, path::Path};
    assert_eq!(
        files::encrypted_path(Path::new("a.tar.gz")).unwrap(),
        Path::new("a.tar.gz.esb")
    );
    for suite in SUITES {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("한글 파일.tar.gz");
        fs::write(&source, b"original data").unwrap();
        files::run(
            &source,
            None,
            PASSWORD,
            Operation::Encrypt(suite),
            &mut |_| true,
        )
        .unwrap();
        let encrypted = files::encrypted_path(&source).unwrap();
        let directory = root.path().join("restore");
        fs::create_dir(&directory).unwrap();
        assert!(files::decrypt_into(&encrypted, &directory, b"wrong", &mut |_| true).is_err());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        let mut kdf_calls = 0;
        let mut observer = |p: Progress| {
            if p.stage == Stage::Kdf {
                kdf_calls += 1;
            }
            true
        };
        let prepared = files::prepare_decryption(&encrypted, PASSWORD, &mut observer).unwrap();
        assert_eq!(prepared.filename(), "한글 파일.tar.gz");
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        let destination = prepared.output_in(&directory).unwrap();
        prepared.save(&destination, &mut observer).unwrap();
        assert_eq!(kdf_calls, 1);
        assert_eq!(fs::read(&destination).unwrap(), b"original data");
        assert!(matches!(
            files::decrypt_into(&encrypted, &directory, PASSWORD, &mut |_| true),
            Err(Error::OutputExists)
        ));
        assert!(matches!(
            files::decrypt_into(&encrypted, root.path(), PASSWORD, &mut |_| true),
            Err(Error::OutputExists)
        ));
        assert_eq!(fs::read(&source).unwrap(), b"original data");

        let prepared = files::prepare_decryption(&encrypted, PASSWORD, &mut |_| true).unwrap();
        fs::write(&encrypted, b"changed while choosing a destination").unwrap();
        let renamed = directory.join("renamed.bin");
        assert!(matches!(
            prepared.save(&renamed, &mut |_| true),
            Err(Error::InputChanged)
        ));
        assert!(!renamed.exists());

        let mut corrupted = fixed(suite, b"data");
        *corrupted.last_mut().unwrap() ^= 1;
        fs::write(&encrypted, corrupted).unwrap();
        let prepared = files::prepare_decryption(&encrypted, PASSWORD, &mut |_| true).unwrap();
        assert_eq!(prepared.filename(), "test.bin");
        assert!(prepared.save(&renamed, &mut |_| true).is_err());
        assert!(!renamed.exists());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
    }
}

#[test]
fn authenticated_filename_validation_and_legacy_empty_name() {
    use crate::files;
    use std::fs;
    for suite in SUITES {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input.esb");
        let h = Header::new(suite, [0x11; 16], [0x22; 16]);
        let keys = Keys::derive(PASSWORD, &h).unwrap();
        for name in [
            "../escape",
            "/absolute",
            "a\\b",
            "CON.txt",
            "a:b",
            "foo.",
            "foo ",
            "bad\nname",
            "a?b",
        ] {
            let mut bytes = h.bytes().to_vec();
            let mut meta = (name.len() as u16).to_le_bytes().to_vec();
            meta.extend_from_slice(name.as_bytes());
            write_record(&mut bytes, &h, &keys, 1, 0, &mut meta).unwrap();
            fs::write(&input, bytes).unwrap();
            assert!(
                files::prepare_decryption(&input, PASSWORD, &mut |_| true).is_err(),
                "{name}"
            );
        }
        let mut bytes = Vec::new();
        encrypt(
            &mut Cursor::new(b"legacy"),
            &mut bytes,
            PASSWORD,
            suite,
            "",
            &mut |_| true,
        )
        .unwrap();
        fs::write(&input, bytes).unwrap();
        let prepared = files::prepare_decryption(&input, PASSWORD, &mut |_| true).unwrap();
        assert!(matches!(
            prepared.output_in(root.path()),
            Err(Error::MissingFilename)
        ));
        let output = root.path().join("chosen.bin");
        prepared.save(&output, &mut |_| true).unwrap();
        assert_eq!(fs::read(output).unwrap(), b"legacy");
    }
}
