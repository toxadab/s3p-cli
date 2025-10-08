//! Core primitives for the S³P toolchain.
//!
//! This crate exposes four foundational building blocks that the rest of the
//! BlockNet stack relies upon:
//!
//! * [`crypto`] — authenticated symmetric encryption using XChaCha20-Poly1305.
//! * [`erasure`] — Reed–Solomon based erasure coding helpers for resilient
//!   storage and transport.
//! * [`merkle`] — Blake3 backed Merkle tree construction utilities.
//! * [`fountain`] — a lightweight fountain code implementation suitable for
//!   streaming large artefacts over unreliable channels.
//!
//! The modules are intentionally small and focused so that higher level crates
//! (CLI, ledger, PoC engine, referral logic, …) can be combined without pulling
//! in heavy dependencies or bespoke plumbing in each consumer.

pub mod crypto;
pub mod erasure;
pub mod fountain;
pub mod merkle;

mod error;

pub use error::S3pError;
