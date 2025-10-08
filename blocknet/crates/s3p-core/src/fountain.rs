use crate::error::S3pError;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

/// Metadata describing the fountain stream.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FountainMetadata {
    pub original_len: usize,
    pub block_len: usize,
    pub block_count: usize,
}

impl FountainMetadata {
    pub fn new(original_len: usize, block_len: usize, block_count: usize) -> Self {
        Self {
            original_len,
            block_len,
            block_count,
        }
    }
}

/// Encoded fountain packet carrying XORed blocks.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FountainPacket {
    pub seed: u64,
    pub indices: Vec<usize>,
    pub payload: Vec<u8>,
    pub metadata: FountainMetadata,
}

/// Streaming encoder implementing a simple LT-style fountain code.
pub struct FountainEncoder {
    blocks: Vec<Vec<u8>>,
    metadata: FountainMetadata,
    systematic_index: usize,
    seed: u64,
}

impl FountainEncoder {
    /// Create an encoder from raw bytes, splitting the payload into
    /// `block_len` sized chunks.
    pub fn from_bytes(data: &[u8], block_len: usize) -> Result<Self, S3pError> {
        if block_len == 0 {
            return Err(S3pError::Fountain("block length must be greater than zero"));
        }
        let block_count = (data.len() + block_len - 1) / block_len;
        let block_count = block_count.max(1);
        let mut blocks = Vec::with_capacity(block_count);
        for chunk in data.chunks(block_len) {
            let mut block = vec![0u8; block_len];
            block[..chunk.len()].copy_from_slice(chunk);
            blocks.push(block);
        }
        while blocks.len() < block_count {
            blocks.push(vec![0u8; block_len]);
        }
        Ok(Self {
            metadata: FountainMetadata::new(data.len(), block_len, block_count),
            blocks,
            systematic_index: 0,
            seed: 0,
        })
    }

    /// Return immutable metadata describing the encoder stream.
    pub fn metadata(&self) -> FountainMetadata {
        self.metadata
    }

    /// Total number of source blocks.
    pub fn block_count(&self) -> usize {
        self.metadata.block_count
    }

    /// Produce the next fountain packet. The encoder first emits all source
    /// blocks in systematic order before switching to probabilistic
    /// combinations that aid recovery in lossy environments.
    pub fn next_packet(&mut self) -> FountainPacket {
        if self.systematic_index < self.metadata.block_count {
            let idx = self.systematic_index;
            self.systematic_index += 1;
            return FountainPacket {
                seed: self.seed,
                indices: vec![idx],
                payload: self.blocks[idx].clone(),
                metadata: self.metadata,
            };
        }

        self.seed = self.seed.wrapping_add(1);
        let mut rng = StdRng::seed_from_u64(self.seed);
        let degree = sample_degree(self.metadata.block_count, &mut rng);
        let mut indices: Vec<usize> = (0..self.metadata.block_count).collect();
        indices.shuffle(&mut rng);
        indices.truncate(degree);
        indices.sort_unstable();

        let mut payload = vec![0u8; self.metadata.block_len];
        for &idx in &indices {
            xor_in_place(&mut payload, &self.blocks[idx]);
        }

        FountainPacket {
            seed: self.seed,
            indices,
            payload,
            metadata: self.metadata,
        }
    }
}

/// Fountain decoder capable of reconstructing the original payload once
/// enough packets have been received.
pub struct FountainDecoder {
    metadata: FountainMetadata,
    solutions: Vec<Option<Vec<u8>>>,
    equations: Vec<Equation>,
}

struct Equation {
    indices: Vec<usize>,
    payload: Vec<u8>,
}

impl FountainDecoder {
    pub fn new(metadata: FountainMetadata) -> Self {
        let solutions = vec![None; metadata.block_count];
        Self {
            metadata,
            solutions,
            equations: Vec::new(),
        }
    }

    /// Ingest a packet and try to recover additional source blocks. Returns
    /// `Ok(Some(bytes))` once the entire payload has been reconstructed.
    pub fn receive(&mut self, packet: FountainPacket) -> Result<Option<Vec<u8>>, S3pError> {
        if packet.metadata != self.metadata {
            return Err(S3pError::Fountain("metadata mismatch"));
        }
        if packet.payload.len() != self.metadata.block_len {
            return Err(S3pError::Fountain("invalid payload length"));
        }
        if packet.indices.is_empty() {
            return Err(S3pError::Fountain("packet without indices"));
        }

        let mut equation = Equation {
            indices: packet.indices,
            payload: packet.payload,
        };

        reduce_with_known(&mut equation, &self.solutions)?;

        if equation.indices.is_empty() {
            if equation.payload.iter().any(|&b| b != 0) {
                return Err(S3pError::Fountain("inconsistent packet"));
            }
            return Ok(self.try_finalize());
        }

        if equation.indices.len() == 1 {
            let idx = equation.indices[0];
            self.set_solution(idx, equation.payload)?;
        } else {
            self.equations.push(equation);
        }

        self.propagate()?;
        Ok(self.try_finalize())
    }

    fn set_solution(&mut self, idx: usize, payload: Vec<u8>) -> Result<(), S3pError> {
        if idx >= self.metadata.block_count {
            return Err(S3pError::Fountain("block index out of range"));
        }
        if payload.len() != self.metadata.block_len {
            return Err(S3pError::Fountain("invalid block length"));
        }
        match &self.solutions[idx] {
            Some(existing) if existing != &payload => {
                return Err(S3pError::Fountain("conflicting solution"));
            }
            Some(_) => Ok(()),
            None => {
                self.solutions[idx] = Some(payload.clone());
                self.enqueue_solution(idx, payload)?;
                Ok(())
            }
        }
    }

    fn enqueue_solution(&mut self, idx: usize, payload: Vec<u8>) -> Result<(), S3pError> {
        let mut queue = vec![(idx, payload)];
        while let Some((index, value)) = queue.pop() {
            let mut i = 0;
            while i < self.equations.len() {
                if let Some(pos) = self.equations[i].indices.iter().position(|j| *j == index) {
                    self.equations[i].indices.swap_remove(pos);
                    xor_in_place(&mut self.equations[i].payload, &value);
                }

                // Remove any already solved indices.
                let mut j = 0;
                while j < self.equations[i].indices.len() {
                    let candidate = self.equations[i].indices[j];
                    if let Some(solution) = &self.solutions[candidate] {
                        self.equations[i].indices.swap_remove(j);
                        xor_in_place(&mut self.equations[i].payload, solution);
                    } else {
                        j += 1;
                    }
                }

                if self.equations[i].indices.is_empty() {
                    if self.equations[i].payload.iter().any(|&b| b != 0) {
                        return Err(S3pError::Fountain("inconsistent equations"));
                    }
                    self.equations.swap_remove(i);
                    continue;
                }

                if self.equations[i].indices.len() == 1 {
                    let new_idx = self.equations[i].indices[0];
                    let payload = self.equations[i].payload.clone();
                    self.equations.swap_remove(i);
                    if self.solutions[new_idx].is_none() {
                        self.solutions[new_idx] = Some(payload.clone());
                        queue.push((new_idx, payload));
                    } else if self.solutions[new_idx].as_ref().unwrap() != &payload {
                        return Err(S3pError::Fountain("conflicting solution"));
                    }
                    continue;
                }

                i += 1;
            }
        }
        Ok(())
    }

    fn propagate(&mut self) -> Result<(), S3pError> {
        // Re-run elimination in case new equations became solvable.
        let mut i = 0;
        while i < self.equations.len() {
            reduce_with_known(&mut self.equations[i], &self.solutions)?;
            if self.equations[i].indices.is_empty() {
                if self.equations[i].payload.iter().any(|&b| b != 0) {
                    return Err(S3pError::Fountain("inconsistent equations"));
                }
                self.equations.swap_remove(i);
                continue;
            }
            if self.equations[i].indices.len() == 1 {
                let eq = self.equations.swap_remove(i);
                self.set_solution(eq.indices[0], eq.payload)?;
                // set_solution already propagates, so continue without incrementing i.
                continue;
            }
            i += 1;
        }
        Ok(())
    }

    fn try_finalize(&self) -> Option<Vec<u8>> {
        if self.solutions.iter().any(|entry| entry.is_none()) {
            return None;
        }
        let mut data = Vec::with_capacity(self.metadata.block_count * self.metadata.block_len);
        for block in &self.solutions {
            data.extend_from_slice(block.as_ref().expect("block present"));
        }
        data.truncate(self.metadata.original_len);
        Some(data)
    }
}

fn reduce_with_known(
    equation: &mut Equation,
    solutions: &[Option<Vec<u8>>],
) -> Result<(), S3pError> {
    equation.indices.sort_unstable();
    equation.indices.dedup();

    let mut i = 0;
    while i < equation.indices.len() {
        let idx = equation.indices[i];
        if idx >= solutions.len() {
            return Err(S3pError::Fountain("block index out of range"));
        }
        if let Some(solution) = &solutions[idx] {
            xor_in_place(&mut equation.payload, solution);
            equation.indices.swap_remove(i);
        } else {
            i += 1;
        }
    }
    Ok(())
}

fn sample_degree(block_count: usize, rng: &mut StdRng) -> usize {
    if block_count <= 1 {
        return 1;
    }
    let roll: f64 = rng.gen();
    if roll < 0.6 {
        1
    } else if roll < 0.85 {
        2.min(block_count)
    } else {
        let max_degree = block_count.min(5);
        (rng.gen_range(3..=max_degree)).min(block_count)
    }
}

fn xor_in_place(target: &mut [u8], other: &[u8]) {
    for (lhs, rhs) in target.iter_mut().zip(other.iter()) {
        *lhs ^= *rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn fountain_round_trip() {
        let mut rng = rand::thread_rng();
        let len = 16 * 64;
        let mut data = vec![0u8; len];
        rng.fill(&mut data[..]);

        let mut encoder = FountainEncoder::from_bytes(&data, 64).expect("encoder");
        let metadata = encoder.metadata();
        let mut decoder = FountainDecoder::new(metadata);

        // Simulate lossy channel by randomly dropping packets until recovery.
        let mut attempts = 0;
        while attempts < 10_000 {
            attempts += 1;
            let packet = encoder.next_packet();
            if rng.gen_bool(0.15) {
                continue;
            }
            if let Some(output) = decoder.receive(packet).expect("receive") {
                assert_eq!(output, data);
                return;
            }
        }

        panic!("decoder failed to converge");
    }
}
