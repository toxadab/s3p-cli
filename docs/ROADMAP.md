# BlockNet Roadmap

## Iteration 1–2 Focus

### 1. NOS-Ledger Core
- Design state schema combining periodic snapshots and Merkle roots.
- Implement event emission.
- Support NOS emission, budget accounting, and transfers.

### 2. PoC Receipt Pipeline
- Define canonical `receipt{scid, merkleRoot, ctHash, outcome}` structure.
- Implement committee validation and Ed25519 signature aggregation.
- Apply signed receipts to NOS-Ledger state.

### 3. Contract Rules Interface
- Provide configuration for rules, budgets, and steward management.
- Implement referral payouts with `refBps` and level configuration.
- Establish budget-funded execution flows with no end-user fees.

### 4. Service Layer APIs
- Expose lightweight JSON-RPC/REST endpoints wrapping `s3p-cli` (`pack`, `verify`, `unpack`, `fountain`).
- Stream progress and status updates for long-running operations.
- Document error codes and event notifications.

### 5. Web UI MVP
- **RS tab**: finalize and polish user experience.
- **Fountain tab**: support pack/serve/fetch with progress tracking.
- **Contracts tab**: create PoC contracts, fund budgets, launch execution, and review receipts/payouts.

### 6. DevOps Foundations
- Define protobuf/JSON schemas for persistent artifacts.
- Record Merkle roots and hashes within logs for traceability.
- Track tasks and milestones via the issue tracker.

## Open Discussion Topics
1. Committee composition, quorum thresholds, and signature aggregation mechanics.
2. Referral payout depth, caps, and anti-spam safeguards while preserving the gasless experience.
3. API contract between UI and service layer, including endpoints, events, and error handling.

## Build & Environment Notes
- Supported environments: Windows (PowerShell) and Linux.
- Primary build command: `cargo build --release`.
