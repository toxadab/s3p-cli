use crate::error::S3pError;
use hex::ToHex;
use rs_merkle::{Hasher, MerkleProof, MerkleTree};

/// Blake3 powered hasher compatible with `rs_merkle`.
#[derive(Debug, Clone, Copy)]
pub struct Blake3;

impl Hasher for Blake3 {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        *blake3::hash(data).as_bytes()
    }
}

/// Wrapper around `rs_merkle::MerkleTree` that adds convenience helpers.
#[derive(Clone, Debug)]
pub struct Blake3MerkleTree {
    leaves: Vec<[u8; 32]>,
    root: Option<[u8; 32]>,
}

impl Blake3MerkleTree {
    /// Build a tree from pre-hashed leaves.
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        let tree = MerkleTree::<Blake3>::from_leaves(&leaves);
        Self {
            root: tree.root(),
            leaves,
        }
    }

    /// Convenience constructor that hashes raw chunks with Blake3 prior to
    /// building the tree.
    pub fn from_chunks(chunks: &[impl AsRef<[u8]>]) -> Self {
        let leaves = chunks
            .iter()
            .map(|chunk| blake3::hash(chunk.as_ref()).into())
            .collect();
        Self::from_leaves(leaves)
    }

    /// Return the Merkle root (if any leaves were provided).
    pub fn root(&self) -> Option<[u8; 32]> {
        self.root
    }

    /// Render the root as a hex encoded string.
    pub fn root_hex(&self) -> Option<String> {
        self.root.map(|root| root.encode_hex::<String>())
    }

    /// Create an inclusion proof for the specified leaf indices.
    pub fn proof(&self, indices: &[usize]) -> Result<Blake3Proof, S3pError> {
        if indices.iter().any(|&idx| idx >= self.leaves.len()) {
            return Err(S3pError::Merkle("leaf index out of range".into()));
        }
        let tree = MerkleTree::<Blake3>::from_leaves(&self.leaves);
        Ok(Blake3Proof {
            proof: tree.proof(indices),
            leaf_indices: indices.to_vec(),
        })
    }

    /// Verify the provided proof.
    pub fn verify(&self, proof: &Blake3Proof) -> bool {
        if let Some(root) = self.root {
            proof.proof.verify(root, &proof.leaf_indices, &self.leaves)
        } else {
            false
        }
    }
}

/// Serializable wrapper for a Merkle proof.
#[derive(Clone, Debug)]
pub struct Blake3Proof {
    proof: MerkleProof<[u8; 32]>,
    leaf_indices: Vec<usize>,
}

impl Blake3Proof {
    /// Expose the raw leaf indices covered by the proof.
    pub fn leaf_indices(&self) -> &[usize] {
        &self.leaf_indices
    }

    /// Return the raw proof instance.
    pub fn inner(&self) -> &MerkleProof<[u8; 32]> {
        &self.proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_verifies_merkle_tree() {
        let chunks = vec![b"alpha", b"beta", b"gamma", b"delta"];
        let tree = Blake3MerkleTree::from_chunks(&chunks);
        let root = tree.root().expect("root");
        let proof = tree.proof(&[1, 3]).expect("proof");
        assert!(tree.verify(&proof));

        // Tamper the root to ensure the proof fails.
        let mut tampered = root;
        tampered[0] ^= 0xff;
        let hashed_chunks: Vec<[u8; 32]> = chunks
            .iter()
            .map(|chunk| blake3::hash(chunk).into())
            .collect();
        assert!(!proof
            .inner()
            .verify(tampered, proof.leaf_indices(), &hashed_chunks));
    }
}
