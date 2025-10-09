use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::contracts::{BudgetSpendPlan, ReferralPayout};

pub type AccountId = String;
pub type ContractId = String;
pub type BudgetId = String;
pub type Amount = u64;

pub const NOS_SCALE: u64 = 100_000_000; // 1 NOS = 1e8 minimal units

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("insufficient funds in account {account}")]
    InsufficientAccountFunds { account: AccountId },
    #[error("insufficient funds in budget {budget_id}")]
    InsufficientBudgetFunds { budget_id: BudgetId },
    #[error("unknown account {account}")]
    UnknownAccount { account: AccountId },
    #[error("unknown budget {budget_id}")]
    UnknownBudget { budget_id: BudgetId },
    #[error("duplicate receipt detected")]
    DuplicateReceipt,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AccountBalance {
    pub available: Amount,
    pub locked: Amount,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BudgetState {
    pub id: BudgetId,
    pub contract: ContractId,
    pub steward: AccountId,
    pub available: Amount,
}

impl BudgetState {
    pub fn debit(&mut self, amount: Amount) -> Result<(), LedgerError> {
        if self.available < amount {
            return Err(LedgerError::InsufficientBudgetFunds {
                budget_id: self.id.clone(),
            });
        }
        self.available -= amount;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SnapshotMetadata {
    pub height: u64,
    pub timestamp: u64,
    pub previous_receipt: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerSnapshot {
    pub meta: SnapshotMetadata,
    pub accounts: BTreeMap<AccountId, AccountBalance>,
    pub budgets: BTreeMap<BudgetId, BudgetState>,
    pub events: Vec<LedgerEvent>,
    pub merkle_root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LedgerEvent {
    Emission {
        to: AccountId,
        amount: Amount,
        reason: String,
    },
    Transfer {
        from: AccountId,
        to: AccountId,
        amount: Amount,
        memo: Option<String>,
    },
    BudgetFunded {
        from: AccountId,
        budget_id: BudgetId,
        amount: Amount,
        memo: Option<String>,
    },
    BudgetDebited {
        budget_id: BudgetId,
        to: AccountId,
        amount: Amount,
        memo: Option<String>,
    },
    ReferralPayout {
        contract: ContractId,
        recipient: AccountId,
        amount: Amount,
        level: u32,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LedgerMutation {
    Emit {
        to: AccountId,
        amount: Amount,
        reason: String,
    },
    Transfer {
        from: AccountId,
        to: AccountId,
        amount: Amount,
        memo: Option<String>,
    },
    FundBudget {
        from: AccountId,
        budget_id: BudgetId,
        amount: Amount,
        memo: Option<String>,
    },
    SpendBudget {
        budget_id: BudgetId,
        plan: BudgetSpendPlan,
    },
    ApplyReferralPayouts {
        contract: ContractId,
        payouts: Vec<ReferralPayout>,
    },
}

#[derive(Default)]
pub struct LedgerState {
    pub meta: SnapshotMetadata,
    pub accounts: BTreeMap<AccountId, AccountBalance>,
    pub budgets: BTreeMap<BudgetId, BudgetState>,
    pub events: Vec<LedgerEvent>,
    applied_receipts: BTreeMap<[u8; 32], ()>,
}

impl LedgerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn credit_account(&mut self, account: &AccountId, amount: Amount) {
        let balance = self
            .accounts
            .entry(account.clone())
            .or_insert_with(AccountBalance::default);
        balance.available += amount;
    }

    pub fn debit_account(
        &mut self,
        account: &AccountId,
        amount: Amount,
    ) -> Result<(), LedgerError> {
        let balance =
            self.accounts
                .get_mut(account)
                .ok_or_else(|| LedgerError::UnknownAccount {
                    account: account.clone(),
                })?;
        if balance.available < amount {
            return Err(LedgerError::InsufficientAccountFunds {
                account: account.clone(),
            });
        }
        balance.available -= amount;
        Ok(())
    }

    pub fn upsert_budget(&mut self, budget: BudgetState) {
        self.budgets.insert(budget.id.clone(), budget);
    }

    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            meta: self.meta.clone(),
            accounts: self.accounts.clone(),
            budgets: self.budgets.clone(),
            events: self.events.clone(),
            merkle_root: compute_merkle_root(&self.accounts, &self.budgets),
        }
    }

    pub fn apply_mutations(
        &mut self,
        mutations: &[LedgerMutation],
        receipt_id: [u8; 32],
        timestamp: u64,
    ) -> Result<(), LedgerError> {
        if self.applied_receipts.contains_key(&receipt_id) {
            return Err(LedgerError::DuplicateReceipt);
        }

        for mutation in mutations {
            match mutation {
                LedgerMutation::Emit { to, amount, reason } => {
                    self.credit_account(to, *amount);
                    self.events.push(LedgerEvent::Emission {
                        to: to.clone(),
                        amount: *amount,
                        reason: reason.clone(),
                    });
                }
                LedgerMutation::Transfer {
                    from,
                    to,
                    amount,
                    memo,
                } => {
                    self.debit_account(from, *amount)?;
                    self.credit_account(to, *amount);
                    self.events.push(LedgerEvent::Transfer {
                        from: from.clone(),
                        to: to.clone(),
                        amount: *amount,
                        memo: memo.clone(),
                    });
                }
                LedgerMutation::FundBudget {
                    from,
                    budget_id,
                    amount,
                    memo,
                } => {
                    self.debit_account(from, *amount)?;
                    let budget =
                        self.budgets
                            .entry(budget_id.clone())
                            .or_insert_with(|| BudgetState {
                                id: budget_id.clone(),
                                contract: String::new(),
                                steward: from.clone(),
                                available: 0,
                            });
                    budget.available += amount;
                    self.events.push(LedgerEvent::BudgetFunded {
                        from: from.clone(),
                        budget_id: budget_id.clone(),
                        amount: *amount,
                        memo: memo.clone(),
                    });
                }
                LedgerMutation::SpendBudget { budget_id, plan } => {
                    let budget = self.budgets.get_mut(budget_id).ok_or_else(|| {
                        LedgerError::UnknownBudget {
                            budget_id: budget_id.clone(),
                        }
                    })?;
                    let spend_total = plan.total_amount();
                    budget.debit(spend_total)?;
                    for transfer in &plan.transfers {
                        self.credit_account(&transfer.to, transfer.amount);
                        self.events.push(LedgerEvent::BudgetDebited {
                            budget_id: budget_id.clone(),
                            to: transfer.to.clone(),
                            amount: transfer.amount,
                            memo: transfer.memo.clone(),
                        });
                    }
                }
                LedgerMutation::ApplyReferralPayouts { contract, payouts } => {
                    for payout in payouts {
                        self.credit_account(&payout.recipient, payout.amount);
                        self.events.push(LedgerEvent::ReferralPayout {
                            contract: contract.clone(),
                            recipient: payout.recipient.clone(),
                            amount: payout.amount,
                            level: payout.level,
                        });
                    }
                }
            }
        }

        self.meta.height += 1;
        self.meta.timestamp = timestamp;
        self.meta.previous_receipt = Some(receipt_id);
        self.applied_receipts.insert(receipt_id, ());
        Ok(())
    }
}

fn compute_merkle_root(
    accounts: &BTreeMap<AccountId, AccountBalance>,
    budgets: &BTreeMap<BudgetId, BudgetState>,
) -> [u8; 32] {
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    for (account, balance) in accounts {
        let mut hasher = Sha256::new();
        hasher.update(b"acct");
        hasher.update(account.as_bytes());
        hasher.update(balance.available.to_le_bytes());
        hasher.update(balance.locked.to_le_bytes());
        leaves.push(hasher.finalize().into());
    }
    for (budget_id, budget) in budgets {
        let mut hasher = Sha256::new();
        hasher.update(b"budget");
        hasher.update(budget_id.as_bytes());
        hasher.update(budget.contract.as_bytes());
        hasher.update(budget.steward.as_bytes());
        hasher.update(budget.available.to_le_bytes());
        leaves.push(hasher.finalize().into());
    }
    build_merkle(leaves)
}

fn build_merkle(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return Sha256::digest(b"nos-ledger-empty").into();
    }
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        for chunk in leaves.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(b"node");
            hasher.update(&chunk[0]);
            if chunk.len() == 2 {
                hasher.update(&chunk[1]);
            } else {
                hasher.update(&chunk[0]);
            }
            next.push(hasher.finalize().into());
        }
        leaves = next;
    }
    leaves[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_root_is_deterministic() {
        let mut ledger = LedgerState::new();
        ledger.credit_account(&"alice".to_string(), 1_000);
        ledger.credit_account(&"bob".to_string(), 2_000);
        let root1 = ledger.snapshot().merkle_root;
        let root2 = ledger.snapshot().merkle_root;
        assert_eq!(root1, root2);
    }

    #[test]
    fn applying_mutations_updates_balances_and_events() {
        let mut ledger = LedgerState::new();
        ledger.credit_account(&"treasury".to_string(), 10_000);
        ledger.upsert_budget(BudgetState {
            id: "budget-1".into(),
            contract: "contract-1".into(),
            steward: "treasury".into(),
            available: 5_000,
        });
        let plan = BudgetSpendPlan {
            transfers: vec![crate::contracts::BudgetTransfer {
                to: "worker".into(),
                amount: 2_000,
                memo: Some("worker payout".into()),
            }],
        };
        ledger
            .apply_mutations(
                &[
                    LedgerMutation::Transfer {
                        from: "treasury".into(),
                        to: "alice".into(),
                        amount: 1_000,
                        memo: Some("grant".into()),
                    },
                    LedgerMutation::SpendBudget {
                        budget_id: "budget-1".into(),
                        plan,
                    },
                    LedgerMutation::ApplyReferralPayouts {
                        contract: "contract-1".into(),
                        payouts: vec![ReferralPayout {
                            recipient: "ref1".into(),
                            amount: 500,
                            level: 1,
                        }],
                    },
                ],
                [1u8; 32],
                1,
            )
            .unwrap();
        assert_eq!(ledger.accounts["alice"].available, 1_000);
        assert_eq!(ledger.accounts["worker"].available, 2_000);
        assert_eq!(ledger.accounts["ref1"].available, 500);
        assert_eq!(ledger.budgets["budget-1"].available, 3_000);
        assert_eq!(ledger.events.len(), 3);
    }
}
