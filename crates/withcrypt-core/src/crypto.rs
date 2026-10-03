//! Key derivation and record encryption (see docs/format-v1.md).
//!
//! One password produces three secrets through Argon2id and HKDF-SHA256:
//! the PRK (source of per-record AES keys), the XChaCha20 encryption key,
//! and the HMAC key that authenticates the whole plaintext.
use crate::{Error, Header, Result, Suite};
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// HMAC-SHA256 over the original file bytes, stored (encrypted) in FINAL.
pub(crate) type PlainMac = Hmac<Sha256>;

/// All secrets derived for one file. Every buffer is wiped on drop.
pub(crate) struct Keys {
    /// HKDF pseudo-random key; AES-GCM derives a fresh key per record from it.
    prk: Zeroizing<[u8; 32]>,
    /// XChaCha20-Poly1305 key, shared by every record of the file.
    enc: Zeroizing<[u8; 32]>,
    /// Running plaintext HMAC, updated chunk by chunk.
    pub mac: PlainMac,
}
impl Keys {
    /// Runs Argon2id once (64 MiB, 3 passes, 4 lanes) on the password and the
    /// header salt, then expands the result into the per-purpose keys.
    pub fn derive(password: &[u8], h: &Header) -> Result<Self> {
        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }
        let mut master = Zeroizing::new([0; 32]);
        let params = Params::new(65536, 3, 4, Some(32)).map_err(|_| Error::Resource)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        // Fallible allocation, with explicit zeroization of Argon2 working memory.
        let mut memory = Vec::new();
        memory
            .try_reserve_exact(65536)
            .map_err(|_| Error::Resource)?;
        memory.resize(65536, argon2::Block::default());
        let mut memory = Zeroizing::new(memory);
        argon
            .hash_password_into_with_memory(password, h.salt(), &mut *master, &mut memory)
            .map_err(|_| Error::Resource)?;
        // HKDF-Extract turns the Argon2 output into a PRK; the temporary copy
        // inside `extract` is wiped right after it is copied out.
        let (mut extract, _) = Hkdf::<Sha256>::extract(Some(h.salt()), &*master);
        let mut prk = Zeroizing::new([0; 32]);
        prk.copy_from_slice(&extract);
        extract.as_mut_slice().zeroize();
        // HKDF-Expand with distinct labels keeps the keys independent.
        let hk = Hkdf::<Sha256>::from_prk(&*prk).map_err(|_| Error::Resource)?;
        let mut enc = Zeroizing::new([0; 32]);
        hk.expand(b"ESB/v1/encryption", &mut *enc)
            .map_err(|_| Error::Resource)?;
        let mut mac_key = Zeroizing::new([0; 32]);
        // Each suite uses its own HMAC label, so the same password and salt
        // never share an HMAC key across suites.
        let info: &[u8] = match h.suite {
            Suite::XChaCha20Poly1305 => b"ESB/v1/plaintext-hmac",
            Suite::Aes256Gcm => b"ESB/v1/aes-256-gcm/plaintext-hmac",
        };
        hk.expand(info, &mut *mac_key)
            .map_err(|_| Error::Resource)?;
        let mac = <PlainMac as Mac>::new_from_slice(&*mac_key).map_err(|_| Error::Resource)?;
        Ok(Self { prk, enc, mac })
    }
    /// A one-record AES-256-GCM key: HKDF(PRK, label || nonce prefix || index).
    /// One key per record bounds how much data any single GCM key protects.
    pub(crate) fn aes_key(&self, h: &Header, index: u64) -> Result<Zeroizing<[u8; 32]>> {
        let mut info = b"ESB/v1/aes-256-gcm/record-key".to_vec();
        info.extend_from_slice(h.prefix());
        info.extend_from_slice(&index.to_le_bytes());
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::from_prk(&*self.prk)
            .map_err(|_| Error::Resource)?
            .expand(&info, &mut *key)
            .map_err(|_| Error::Resource)?;
        Ok(key)
    }
    /// Encrypts or decrypts one record in place (`data` gains/loses the 16-byte tag).
    ///
    /// The AAD binds the record to the full file header and its own 13-byte
    /// record header, and the nonce embeds the record index, so records cannot
    /// be moved, reordered or spliced in from another file.
    pub fn crypt(
        &self,
        h: &Header,
        r: &[u8; 13],
        index: u64,
        data: &mut Vec<u8>,
        encrypt: bool,
    ) -> Result<()> {
        let mut aad = b"ESB/v1/record".to_vec();
        aad.extend_from_slice(&h.raw);
        aad.extend_from_slice(r);
        match h.suite {
            Suite::XChaCha20Poly1305 => {
                // 24-byte nonce = 16-byte random prefix from the header || LE64(index).
                let cipher = XChaCha20Poly1305::new((&*self.enc).into());
                let mut nonce = [0; 24];
                nonce[..16].copy_from_slice(h.prefix());
                nonce[16..].copy_from_slice(&index.to_le_bytes());
                if encrypt {
                    cipher.encrypt_in_place((&nonce).into(), &aad, data)
                } else {
                    cipher.decrypt_in_place((&nonce).into(), &aad, data)
                }
            }
            Suite::Aes256Gcm => {
                // AES-GCM is enabled only on the supported CPU architectures (x86_64, aarch64).
                if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
                    return Err(Error::Format("이 CPU의 AES 구현은 지원하지 않습니다"));
                }
                // 12-byte nonce = first 4 prefix bytes || LE64(index), with a per-record key.
                let key = self.aes_key(h, index)?;
                let cipher = Aes256Gcm::new((&*key).into());
                let mut nonce = [0; 12];
                nonce[..4].copy_from_slice(&h.prefix()[..4]);
                nonce[4..].copy_from_slice(&index.to_le_bytes());
                if encrypt {
                    cipher.encrypt_in_place((&nonce).into(), &aad, data)
                } else {
                    cipher.decrypt_in_place((&nonce).into(), &aad, data)
                }
            }
        }
        // Any AEAD failure means a wrong password or tampered data; never say which.
        .map_err(|_| Error::Authentication)
    }
}
