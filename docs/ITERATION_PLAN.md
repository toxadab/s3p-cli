# Iteration 1–2 Delivery Plan

This plan breaks down the roadmap goals into sequential, verifiable steps with expected outputs. Each step is grouped by theme and includes the dependencies that must be met before moving forward.

## Step 0 – Shared Foundations
- **Objectives**: Finalize cross-cutting decisions before implementation begins.
- **Tasks**:
  - Confirm committee size, quorum, and Ed25519 aggregation approach for PoC validation.
  - Agree on referral payout depth, caps, and anti-abuse quotas.
  - Lock in API envelope (transport, error schema, pagination conventions) for the service layer.
- **Deliverables**:
  - Decision records in `docs/CONTEXT.md` (Consensus, Economics, Interop sections) and/or issues.
  - Updated protobuf/JSON schema drafts capturing receipt, ledger snapshot, and payout messages.
- **Dependencies**: None.

## Step 1 – NOS-Ledger Schema & Storage
- **Objectives**: Design the canonical state layout that PoC receipts will mutate.
- **Tasks**:
  - Define snapshot format, Merkle tree structure, and pruning cadence.
  - Specify event categories and payload schema.
  - Describe emission, budget, and transfer accounting flows.
- **Deliverables**:
  - `docs/specs/nos-ledger.md` capturing diagrams, field tables, and invariants.
  - Draft Rust module skeletons (`src/ledger/mod.rs`, data types, trait bounds) checked in behind `#[cfg(feature = "ledger")]`.
- **Dependencies**: Step 0 decisions on committee outputs that touch ledger state.

## Step 2 – PoC Receipt Lifecycle
- **Objectives**: Formalize how receipts are produced, signed, and applied.
- **Tasks**:
  - Detail the `receipt{scid, merkle_root, ct_hash, outcome}` encoding, hashing, and signature envelope.
  - Define committee validation pipeline, quorum verification, and aggregated signature handling.
  - Describe ledger application flow, including conflict detection and idempotency rules.
- **Deliverables**:
  - `docs/specs/poc-receipts.md` with sequence diagrams and validation logic.
  - Rust prototypes for receipt structs, signature verification helpers, and merkle root reconciliation tests (`src/poc/` namespace).
- **Dependencies**: Step 1 schema for how receipts mutate state; Step 0 committee decisions.

## Step 3 – Contract Rules & Referral Engine
- **Objectives**: Translate business rules into executable configuration.
- **Tasks**:
  - Model contract definition (rules, budget, steward roles) and lifecycle states.
  - Specify referral tree representation, level caps, rate configuration (`refBps`), and anti-spam thresholds.
  - Outline how budgets fund computation and payouts without user fees.
- **Deliverables**:
  - `docs/specs/contracts.md` including rule templates and state diagrams.
  - Rust module scaffolding (`src/contracts/`) with data models, validation traits, and referral payout calculators (unit-test stubs).
- **Dependencies**: Step 1 ledger accounts/budgets; Step 2 receipt application semantics.

## Step 4 – Service Layer APIs
- **Objectives**: Provide the integration contract for external clients.
- **Tasks**:
  - Map CLI capabilities (`pack`, `verify`, `unpack`, `fountain`) to REST/JSON-RPC endpoints.
  - Define authentication, rate limiting, and streaming progress channels.
  - Document error codes, retry semantics, and webhook/event notifications.
- **Deliverables**:
  - `docs/specs/service-api.md` with endpoint tables, request/response bodies, and examples.
  - Server harness skeleton (`src/service/`) exposing stub endpoints and integration tests for contract (using `warp` or `axum`).
- **Dependencies**: Step 0 API envelope decisions; Steps 1–3 data models.

## Step 5 – Web UI MVP
- **Objectives**: Build user flows on top of the service layer.
- **Tasks**:
  - Finalize RS tab UX and QA existing functionality.
  - Implement Fountain tab pack/serve/fetch flows with progress indicator wiring to service events.
  - Create Contracts tab for contract creation, funding, execution, and receipt/payout visualization.
- **Deliverables**:
  - UX mockups or Storybook references captured in `docs/ui/`.
  - Front-end repository updates (separate project) with integration tests hitting local service mocks.
- **Dependencies**: Step 4 API contract; Steps 1–3 data semantics.

## Step 6 – DevOps & Observability
- **Objectives**: Ensure artifacts and processes are trackable and reproducible.
- **Tasks**:
  - Solidify protobuf/JSON schema versions, add CI validation, and publish to registry.
  - Instrument logging to capture Merkle roots, receipt hashes, and payout summaries.
  - Bootstrap issue tracker workflows, including milestone templates and automation.
- **Deliverables**:
  - `docs/devops/observability.md` documenting log fields, dashboards, and alert thresholds.
  - CI/CD configuration updates (`.github/workflows/` or alternative) to enforce formatting, tests, and schema checks.
- **Dependencies**: Steps 1–5 implementations to know what to monitor.

## Tracking & Checkpoints
- Establish fortnightly demos aligned to Steps 1–6 completion.
- Maintain Kanban board referencing this plan; each deliverable tracked as an issue with acceptance criteria.
- Review plan at the end of iteration 1; adjust scope for iteration 2 based on velocity and feedback.

