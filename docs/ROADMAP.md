# BlockNet Roadmap

## Iteration 1–2 Focus

The high-level objectives below are executed through the step-by-step plan in [`docs/ITERATION_PLAN.md`](./ITERATION_PLAN.md). Each roadmap area maps to one or more numbered steps so we can track sequencing and dependencies explicitly.

### 1. NOS-Ledger Core _(Plan Step 1)_
- Design state schema combining periodic snapshots and Merkle roots.
- Implement event emission.
- Support NOS emission, budget accounting, and transfers.

### 2. PoC Receipt Pipeline _(Plan Step 2)_
- Define canonical `receipt{scid, merkleRoot, ctHash, outcome}` structure.
- Implement committee validation and Ed25519 signature aggregation.
- Apply signed receipts to NOS-Ledger state.

### 3. Contract Rules Interface _(Plan Step 3)_
- Provide configuration for rules, budgets, and steward management.
- Implement referral payouts with `refBps` and level configuration.
- Establish budget-funded execution flows with no end-user fees.

### 4. Service Layer APIs _(Plan Step 4)_
- Expose lightweight JSON-RPC/REST endpoints wrapping `s3p-cli` (`pack`, `verify`, `unpack`, `fountain`).
- Stream progress and status updates for long-running operations.
- Document error codes and event notifications.

### 5. Web UI MVP _(Plan Step 5)_
- **RS tab**: finalize and polish user experience.
- **Fountain tab**: support pack/serve/fetch with progress tracking.
- **Contracts tab**: create PoC contracts, fund budgets, launch execution, and review receipts/payouts.

### 6. DevOps Foundations _(Plan Step 6)_
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
