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

pub(crate) type PlainMac = Hmac<Sha256>;
pub(crate) struct Keys {
    prk: Zeroizing<[u8; 32]>,
    enc: Zeroizing<[u8; 32]>,
    pub mac: PlainMac,
}
impl Keys {
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
        let (mut extract, _) = Hkdf::<Sha256>::extract(Some(h.salt()), &*master);
        let mut prk = Zeroizing::new([0; 32]);
        prk.copy_from_slice(&extract);
        extract.as_mut_slice().zeroize();
        let hk = Hkdf::<Sha256>::from_prk(&*prk).map_err(|_| Error::Resource)?;
        let mut enc = Zeroizing::new([0; 32]);
        hk.expand(b"ESB/v1/encryption", &mut *enc)
            .map_err(|_| Error::Resource)?;
        let mut mac_key = Zeroizing::new([0; 32]);
        let info: &[u8] = match h.suite {
            Suite::XChaCha20Poly1305 => b"ESB/v1/plaintext-hmac",
            Suite::Aes256Gcm => b"ESB/v1/aes-256-gcm/plaintext-hmac",
        };
        hk.expand(info, &mut *mac_key)
            .map_err(|_| Error::Resource)?;
        let mac = <PlainMac as Mac>::new_from_slice(&*mac_key).map_err(|_| Error::Resource)?;
        Ok(Self { prk, enc, mac })
    }
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
                if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
                    return Err(Error::Format("이 CPU의 AES 구현은 지원하지 않습니다"));
                }
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
        .map_err(|_| Error::Authentication)
    }
}
