use crate::error::S3pError;
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};

/// Metadata describing a Reed–Solomon shard set.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardMetadata {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_len: usize,
    pub original_len: usize,
}

impl ShardMetadata {
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}

/// A complete erasure coded payload (metadata + shards).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardedBlob {
    pub meta: ShardMetadata,
    pub shards: Vec<Vec<u8>>,
}

impl ShardedBlob {
    pub fn new(meta: ShardMetadata, shards: Vec<Vec<u8>>) -> Self {
        Self { meta, shards }
    }
}

/// Split a buffer into Reed–Solomon shards (systematic encoding).
pub fn encode(
    data: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<ShardedBlob, S3pError> {
    let rs = ReedSolomon::new(data_shards, parity_shards)?;
    let shard_len = (data.len() + data_shards - 1) / data_shards;
    let mut shards = vec![vec![0u8; shard_len]; data_shards + parity_shards];

    for (i, chunk) in data.chunks(shard_len).enumerate() {
        shards[i][..chunk.len()].copy_from_slice(chunk);
    }

    rs.encode(&mut shards)?;

    let meta = ShardMetadata {
        data_shards,
        parity_shards,
        shard_len,
        original_len: data.len(),
    };
    Ok(ShardedBlob::new(meta, shards))
}

/// Attempt to reconstruct the original data from the provided shard set.
///
/// Missing shards can be expressed as `None`. The caller must ensure the
/// `Vec` length equals `meta.total_shards()`.
pub fn reconstruct(
    meta: &ShardMetadata,
    mut shards: Vec<Option<Vec<u8>>>,
) -> Result<Vec<u8>, S3pError> {
    if shards.len() != meta.total_shards() {
        return Err(S3pError::ReedSolomon(
            reed_solomon_erasure::Error::TooFewShards,
        ));
    }

    let rs = ReedSolomon::new(meta.data_shards, meta.parity_shards)?;

    for shard in shards.iter_mut() {
        if shard.is_none() {
            *shard = Some(vec![0u8; meta.shard_len]);
        }
    }

    let mut refs: Vec<Option<&mut [u8]>> = shards
        .iter_mut()
        .map(|shard| shard.as_mut().map(|buf| buf.as_mut_slice()))
        .collect();

    rs.reconstruct(&mut refs)?;

    let mut data = Vec::with_capacity(meta.data_shards * meta.shard_len);
    for idx in 0..meta.data_shards {
        if let Some(shard) = shards[idx].as_ref() {
            data.extend_from_slice(shard);
        }
    }
    data.truncate(meta.original_len);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    #[test]
    fn round_trip_erasure() {
        let data = b"blocknet rocks".repeat(32);
        let blob = encode(&data, 4, 2).expect("encode");

        let mut shards: Vec<Option<Vec<u8>>> = blob.shards.iter().cloned().map(Some).collect();

        // Drop two random shards.
        let mut rng = thread_rng();
        let mut indices: Vec<usize> = (0..shards.len()).collect();
        indices.shuffle(&mut rng);
        for idx in indices.into_iter().take(2) {
            shards[idx] = None;
        }

        let recovered = reconstruct(&blob.meta, shards).expect("reconstruct");
        assert_eq!(recovered, data);
    }
}
