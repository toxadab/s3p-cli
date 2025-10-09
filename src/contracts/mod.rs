use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ledger::{AccountId, Amount, BudgetId, ContractId, LedgerMutation};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractDefinition {
    pub id: ContractId,
    pub steward: AccountId,
    pub budget_id: BudgetId,
    pub referral: ReferralConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReferralConfig {
    pub levels_bps: Vec<u32>,
    pub minimum_payout: Amount,
    pub level_cap: Option<u32>,
    pub participant_quota: Option<u32>,
}

impl ReferralConfig {
    pub fn max_depth(&self) -> usize {
        match self.level_cap {
            Some(cap) => cap as usize,
            None => self.levels_bps.len(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReferralPayout {
    pub recipient: AccountId,
    pub amount: Amount,
    pub level: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BudgetTransfer {
    pub to: AccountId,
    pub amount: Amount,
    pub memo: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BudgetSpendPlan {
    pub transfers: Vec<BudgetTransfer>,
}

impl BudgetSpendPlan {
    pub fn total_amount(&self) -> Amount {
        self.transfers.iter().map(|t| t.amount).sum()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ReferralTree {
    sponsors: BTreeMap<AccountId, AccountId>,
    quotas: BTreeMap<AccountId, u32>,
}

impl ReferralTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn link(&mut self, sponsor: AccountId, invitee: AccountId, max_children: Option<u32>) {
        self.sponsors.insert(invitee.clone(), sponsor.clone());
        if let Some(cap) = max_children {
            let entry = self.quotas.entry(sponsor).or_default();
            *entry = entry.saturating_add(1).min(cap);
        }
    }

    pub fn ancestry(&self, mut node: AccountId, limit: usize) -> Vec<AccountId> {
        let mut chain = Vec::new();
        let mut visited = BTreeSet::new();
        while let Some(parent) = self.sponsors.get(&node) {
            if !visited.insert(parent.clone()) {
                break;
            }
            chain.push(parent.clone());
            if chain.len() >= limit {
                break;
            }
            node = parent.clone();
        }
        chain
    }
}

pub struct ReferralEngine<'a> {
    config: &'a ReferralConfig,
    tree: &'a ReferralTree,
}

impl<'a> ReferralEngine<'a> {
    pub fn new(config: &'a ReferralConfig, tree: &'a ReferralTree) -> Self {
        Self { config, tree }
    }

    pub fn calculate_payouts(
        &self,
        trigger_amount: Amount,
        origin: &AccountId,
    ) -> Vec<ReferralPayout> {
        if trigger_amount == 0 {
            return vec![];
        }
        let mut payouts = Vec::new();
        let levels = self.config.levels_bps.len().min(self.config.max_depth());
        let chain = self.tree.ancestry(origin.clone(), levels);
        for (idx, account) in chain.iter().enumerate() {
            let bps = match self.config.levels_bps.get(idx) {
                Some(v) => *v,
                None => break,
            };
            if bps == 0 {
                continue;
            }
            let amount = trigger_amount * bps as u64 / 10_000;
            if amount < self.config.minimum_payout {
                continue;
            }
            payouts.push(ReferralPayout {
                recipient: account.clone(),
                amount,
                level: (idx + 1) as u32,
            });
        }
        payouts
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContractAction {
    FundBudget {
        from: AccountId,
        amount: Amount,
        memo: Option<String>,
    },
    ExecuteWork {
        worker: AccountId,
        payout: Amount,
        referral_origin: Option<AccountId>,
    },
}

impl ContractDefinition {
    pub fn apply_action(&self, action: ContractAction, tree: &ReferralTree) -> Vec<LedgerMutation> {
        match action {
            ContractAction::FundBudget { from, amount, memo } => vec![LedgerMutation::FundBudget {
                from,
                budget_id: self.budget_id.clone(),
                amount,
                memo,
            }],
            ContractAction::ExecuteWork {
                worker,
                payout,
                referral_origin,
            } => {
                let mut mutations = Vec::new();
                let mut plan = BudgetSpendPlan {
                    transfers: vec![BudgetTransfer {
                        to: worker,
                        amount: payout,
                        memo: Some(format!("contract:{} payout", self.id)),
                    }],
                };
                let mut referral_payouts = Vec::new();
                if let Some(origin) = referral_origin {
                    let engine = ReferralEngine::new(&self.referral, tree);
                    referral_payouts = engine.calculate_payouts(payout, &origin);
                }
                if !referral_payouts.is_empty() {
                    for payout in &referral_payouts {
                        plan.transfers.push(BudgetTransfer {
                            to: payout.recipient.clone(),
                            amount: payout.amount,
                            memo: Some(format!("contract:{} referral L{}", self.id, payout.level)),
                        });
                    }
                }
                mutations.push(LedgerMutation::SpendBudget {
                    budget_id: self.budget_id.clone(),
                    plan,
                });
                if !referral_payouts.is_empty() {
                    mutations.push(LedgerMutation::ApplyReferralPayouts {
                        contract: self.id.clone(),
                        payouts: referral_payouts,
                    });
                }
                mutations
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn referral_engine_respects_minimum_payouts_and_depth() {
        let config = ReferralConfig {
            levels_bps: vec![1_000, 500, 250],
            minimum_payout: 10,
            level_cap: Some(2),
            participant_quota: None,
        };
        let mut tree = ReferralTree::new();
        tree.link("root".into(), "alice".into(), None);
        tree.link("alice".into(), "bob".into(), None);
        tree.link("bob".into(), "carol".into(), None);
        let engine = ReferralEngine::new(&config, &tree);
        let payouts = engine.calculate_payouts(10_000, &"carol".into());
        assert_eq!(payouts.len(), 2);
        assert_eq!(payouts[0].recipient, "bob");
        assert_eq!(payouts[0].amount, 1_000);
        assert_eq!(payouts[1].recipient, "alice");
        assert_eq!(payouts[1].amount, 500);
    }

    #[test]
    fn contract_action_generates_budget_and_referral_mutations() {
        let contract = ContractDefinition {
            id: "contract-1".into(),
            steward: "steward".into(),
            budget_id: "budget-1".into(),
            referral: ReferralConfig {
                levels_bps: vec![1_000],
                minimum_payout: 1,
                level_cap: None,
                participant_quota: None,
            },
        };
        let mut tree = ReferralTree::new();
        tree.link("alice".into(), "bob".into(), None);
        let actions = contract.apply_action(
            ContractAction::ExecuteWork {
                worker: "worker".into(),
                payout: 5_000,
                referral_origin: Some("bob".into()),
            },
            &tree,
        );
        assert_eq!(actions.len(), 2);
        match &actions[0] {
            LedgerMutation::SpendBudget { budget_id, plan } => {
                assert_eq!(budget_id, "budget-1");
                assert_eq!(plan.transfers.len(), 2);
            }
            _ => panic!("expected spend budget"),
        }
    }
}
