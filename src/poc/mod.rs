use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ledger::LedgerMutation;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptCore {
    pub scid: String,
    pub merkle_root: [u8; 32],
    pub ct_hash: [u8; 32],
    pub outcome: ReceiptOutcome,
}

impl ReceiptCore {
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.scid.as_bytes());
        hasher.update(&self.merkle_root);
        hasher.update(&self.ct_hash);
        hasher.update(self.outcome.commitment().as_slice());
        hasher.finalize().into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedReceipt {
    pub core: ReceiptCore,
    pub committee: CommitteeEnvelope,
}

impl SignedReceipt {
    pub fn digest(&self) -> [u8; 32] {
        self.core.digest()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitteeEnvelope {
    pub signatures: Vec<MemberSignature>,
    pub aggregated: Option<AggregatedSignature>,
}

impl CommitteeEnvelope {
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
            aggregated: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberSignature {
    pub member_id: String,
    #[serde(with = "crate::poc::serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregatedSignature {
    pub participants: Vec<String>,
    #[serde(with = "crate::poc::serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReceiptOutcome {
    Accepted {
        mutations: Vec<LedgerMutation>,
        notes: Vec<String>,
    },
    Rejected {
        reason: String,
    },
}

impl ReceiptOutcome {
    pub fn commitment(&self) -> Vec<u8> {
        match self {
            ReceiptOutcome::Accepted { mutations, notes } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"accepted");
                buf.extend_from_slice(&(mutations.len() as u64).to_le_bytes());
                for mutation in mutations {
                    buf.extend(serde_json::to_vec(mutation).expect("mutation encode"));
                }
                for note in notes {
                    buf.extend_from_slice(note.as_bytes());
                }
                buf
            }
            ReceiptOutcome::Rejected { reason } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"rejected");
                buf.extend_from_slice(reason.as_bytes());
                buf
            }
        }
    }
}

#[derive(Clone)]
pub struct CommitteeConfig {
    pub quorum: usize,
    pub members: BTreeMap<String, VerifyingKey>,
}

impl CommitteeConfig {
    pub fn new(members: Vec<(String, VerifyingKey)>, quorum: usize) -> Self {
        let members_map = members.into_iter().collect();
        Self {
            quorum,
            members: members_map,
        }
    }

    pub fn member_ids(&self) -> Vec<String> {
        self.members.keys().cloned().collect()
    }

    pub fn verify(&self, receipt: &SignedReceipt) -> Result<(), VerificationError> {
        let digest = receipt.digest();
        let mut verified = BTreeSet::new();
        for sig in &receipt.committee.signatures {
            let key = self
                .members
                .get(&sig.member_id)
                .ok_or_else(|| VerificationError::UnknownMember(sig.member_id.clone()))?;
            let signature = Signature::from_slice(&sig.signature)
                .map_err(|_| VerificationError::MalformedSignature(sig.member_id.clone()))?;
            key.verify_strict(&digest, &signature)
                .map_err(|_| VerificationError::InvalidSignature(sig.member_id.clone()))?;
            verified.insert(sig.member_id.clone());
        }
        if let Some(agg) = &receipt.committee.aggregated {
            for member in &agg.participants {
                if !self.members.contains_key(member) {
                    return Err(VerificationError::UnknownMember(member.clone()));
                }
            }
            // Until an aggregation scheme is wired, we treat aggregated signatures as advisory.
        }
        if verified.len() < self.quorum {
            return Err(VerificationError::InsufficientQuorum {
                expected: self.quorum,
                actual: verified.len(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("signature from unknown committee member {0}")]
    UnknownMember(String),
    #[error("malformed signature from member {0}")]
    MalformedSignature(String),
    #[error("invalid signature from member {0}")]
    InvalidSignature(String),
    #[error("receipt signed by {actual} members, quorum {expected}")]
    InsufficientQuorum { expected: usize, actual: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn random_committee(size: usize, quorum: usize) -> (CommitteeConfig, Vec<SigningKey>) {
        let mut rng = OsRng;
        let mut members = Vec::new();
        let mut signing_keys = Vec::new();
        for idx in 0..size {
            let sk = SigningKey::generate(&mut rng);
            let pk = sk.verifying_key();
            members.push((format!("member-{idx}"), pk.clone()));
            signing_keys.push(sk);
        }
        (CommitteeConfig::new(members, quorum), signing_keys)
    }

    #[test]
    fn committee_verifies_quorum() {
        let (committee, sks) = random_committee(4, 3);
        let receipt_core = ReceiptCore {
            scid: "set-1".into(),
            merkle_root: [1u8; 32],
            ct_hash: [2u8; 32],
            outcome: ReceiptOutcome::Rejected {
                reason: "invalid ciphertext".into(),
            },
        };
        let digest = receipt_core.digest();
        let mut envelope = CommitteeEnvelope::new();
        for idx in 0..3 {
            let sig = sks[idx].sign(&digest);
            envelope.signatures.push(MemberSignature {
                member_id: format!("member-{idx}"),
                signature: sig.to_bytes().to_vec(),
            });
        }
        let receipt = SignedReceipt {
            core: receipt_core,
            committee: envelope,
        };
        committee.verify(&receipt).unwrap();
    }

    #[test]
    fn insufficient_quorum_fails() {
        let (committee, sks) = random_committee(3, 3);
        let receipt_core = ReceiptCore {
            scid: "set-1".into(),
            merkle_root: [1u8; 32],
            ct_hash: [2u8; 32],
            outcome: ReceiptOutcome::Accepted {
                mutations: vec![],
                notes: vec![],
            },
        };
        let digest = receipt_core.digest();
        let mut envelope = CommitteeEnvelope::new();
        for idx in 0..2 {
            let sig = sks[idx].sign(&digest);
            envelope.signatures.push(MemberSignature {
                member_id: format!("member-{idx}"),
                signature: sig.to_bytes().to_vec(),
            });
        }
        let receipt = SignedReceipt {
            core: receipt_core,
            committee: envelope,
        };
        let err = committee.verify(&receipt).unwrap_err();
        match err {
            VerificationError::InsufficientQuorum { expected, actual } => {
                assert_eq!(expected, 3);
                assert_eq!(actual, 2);
            }
            _ => panic!("unexpected error"),
        }
    }
}

pub(crate) mod serde_bytes {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        hex::decode(&encoded).map_err(D::Error::custom)
    }
}
