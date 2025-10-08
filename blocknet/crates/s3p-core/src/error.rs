use thiserror::Error;

/// Canonical error type exposed by the core primitives.
#[derive(Debug, Error)]
pub enum S3pError {
    /// Encryption/Decryption failure when using the symmetric primitives.
    #[error("encryption failure: {0}")]
    Encryption(&'static str),

    /// Invalid nonce material supplied to the crypto helper routines.
    #[error("invalid nonce length")]
    InvalidNonce,

    /// Reed–Solomon erasure coding failure.
    #[error("reed-solomon error: {0}")]
    ReedSolomon(#[from] reed_solomon_erasure::Error),

    /// Merkle tree builder failure.
    #[error("merkle error: {0}")]
    Merkle(String),

    /// Fountain coding failure.
    #[error("fountain error: {0}")]
    Fountain(&'static str),
}
