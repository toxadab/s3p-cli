# BlockNet Monorepo

This repository hosts the BlockNet toolchain and application stack. The
layout keeps core crates, adapters, and end-user applications in a single
workspace so development can evolve in lock-step.

```
blocknet/
  crates/
    s3p-core/          # cryptographic + storage primitives (migrated from upstream)
    s3p-cli/           # command-line utilities (current crate)
    nos-ledger/        # NOS accounting state machine (new)
    poc-engine/        # Proof-of-Contract lifecycle engine (new)
    referral-module/   # Referral graph and payout logic (new)
  adapters/
    evm-gateway/       # placeholder for external chain gateways
  apps/
    web-ui/            # administrative and participant-facing front-end
```

The initial focus is Phase A of the roadmap: delivering NOS ledger,
Proof-of-Contract, and referral modules with CLI and web tooling. Phase B
will introduce external adapters and anchoring services.
