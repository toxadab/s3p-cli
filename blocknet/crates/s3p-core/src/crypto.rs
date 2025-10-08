use crate::error::S3pError;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;

/// Wrapper around an XChaCha20-Poly1305 key that zeroises memory on drop.
#[derive(Clone, Debug)]
pub struct SymmetricKey {
    inner: Zeroizing<[u8; KEY_SIZE]>,
}

impl SymmetricKey {
    /// Generate a fresh random key.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; KEY_SIZE]);
        OsRng.fill_bytes(&mut *bytes);
        Self { inner: bytes }
    }

    /// Construct a key from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self {
            inner: Zeroizing::new(bytes),
        }
    }

    /// Borrow the raw key material.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.inner
    }

    fn into_key(&self) -> Key {
        *Key::from_slice(self.inner.as_ref())
    }

    /// Encrypt `plaintext` using the provided `nonce` and optional `aad`.
    pub fn seal(&self, nonce: &Nonce, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, S3pError> {
        let cipher = XChaCha20Poly1305::new(&self.into_key());
        cipher
            .encrypt(
                XNonce::from_slice(&nonce.inner),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| S3pError::Encryption("unable to seal payload"))
    }

    /// Decrypt `ciphertext` produced by [`SymmetricKey::seal`].
    pub fn open(&self, nonce: &Nonce, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, S3pError> {
        let cipher = XChaCha20Poly1305::new(&self.into_key());
        cipher
            .decrypt(
                XNonce::from_slice(&nonce.inner),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| S3pError::Encryption("unable to open payload"))
    }

    /// Convenience helper that returns the ciphertext alongside the nonce.
    pub fn seal_random_nonce(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptedMessage, S3pError> {
        let nonce = Nonce::random();
        let ciphertext = self.seal(&nonce, plaintext, aad)?;
        Ok(EncryptedMessage {
            nonce: nonce.inner,
            ciphertext,
        })
    }
}

/// 192-bit nonce used for XChaCha20.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce {
    inner: [u8; NONCE_SIZE],
}

impl Nonce {
    /// Generate a random nonce suitable for a single use with XChaCha20.
    pub fn random() -> Self {
        let mut inner = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut inner);
        Self { inner }
    }

    /// Construct a nonce from raw bytes. Returns an error if the size is
    /// incorrect.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, S3pError> {
        if bytes.len() != NONCE_SIZE {
            return Err(S3pError::InvalidNonce);
        }
        let mut inner = [0u8; NONCE_SIZE];
        inner.copy_from_slice(bytes);
        Ok(Self { inner })
    }

    /// Borrow the inner bytes.
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.inner
    }
}

/// Serializable envelope returned by [`SymmetricKey::seal_random_nonce`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Decrypt the envelope with the provided key and associated data.
    pub fn open(&self, key: &SymmetricKey, aad: &[u8]) -> Result<Vec<u8>, S3pError> {
        let nonce = Nonce { inner: self.nonce };
        key.open(&nonce, &self.ciphertext, aad)
    }
}
