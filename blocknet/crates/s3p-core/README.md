# s3p-core

`s3p-core` packages the reusable primitives that power the S³P toolchain and
upcoming BlockNet services. It exposes:

- XChaCha20-Poly1305 helpers for authenticated encryption.
- Reed–Solomon erasure coding helpers with metadata tracking.
- Blake3-based Merkle tree utilities for producing and verifying proofs.
- A lightweight fountain-code implementation for resilient streaming.

These modules are consumed by the CLI, ledger, PoC engine, and referral
components to keep higher level crates slim and cohesive.
