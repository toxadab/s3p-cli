# BlockNet Platform Context

## Mission
- Autonomous BlockNet network with gas-free user experience.
- Native currency: **NOS**.

## Consensus: Proof of Contract (PoC)
1. Off-chain rules are executed to produce receipts.
2. Receipts contain `scid`, `merkle_root`, `ct_hash`, and `outcome`.
3. A committee of nodes validates receipts and adds aggregated Ed25519 signatures.

## Economics
- Rewards are paid for useful work and participation, including referral incentives.
- Contract or program budgets cover execution and service costs.

## Interoperability
- Optional adapters for EVM, Solana, and TON without degrading the gasless UX.

## Immediate Iteration Goals (1–2)
1. **NOS-Ledger Core**
   - State schema with snapshots and Merkle root.
   - Event system.
   - Emission, budgets, and transfers.
2. **PoC Receipts**
   - Receipt format `receipt{scid, merkleRoot, ctHash, outcome}`.
   - Committee signatures (Ed25519, aggregated).
3. **Contract Rules**
   - Interface: rules + budget + stewards.
   - Referral payouts (`refBps`, levels).
4. **Service Layer**
   - Lightweight JSON-RPC/REST wrapping `s3p-cli` (pack/verify/unpack/fountain) for UI integration.
5. **Web UI MVP**
   - RS tab (polish UX).
   - Fountain tab (pack/serve/fetch with progress/status).
   - Contracts tab (create PoC, fund budget, start execution, view receipts/payouts).
6. **DevOps**
   - Protobuf/JSON schemas for artifacts.
   - Log Merkle roots and hashes.
   - Issue tracker for tasks.

## Key Artifacts & Terms
- `scid`: set identifier.
- `merkle_root`: state root.
- `ct_hash`: ciphertext hash.
- Signed receipts update NOS-Ledger state; contract budgets finance computation and services.

## Project Practice
- Repositories hold the source of truth: `docs/CONTEXT.md`, `docs/ROADMAP.md`, [`docs/ITERATION_PLAN.md`](./ITERATION_PLAN.md), and Issues/Milestones.
- Discussions happen in chat; significant decisions are captured in docs and issues.
- Target environments: Windows/PowerShell and Linux.
- Build command: `cargo build --release`.

## Discussion Priorities
1. Committee model (size, quorum, signature aggregation) and receipt publication flow.
2. Referral payout model (depth, caps, anti-spam quotas) while maintaining gasless UX.
3. API formats between UI and service layer (endpoints, events, error codes).
