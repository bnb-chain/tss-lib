// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/crypto/commitments/commitment_builder.go

use num_bigint_dig::BigInt;
use num_traits::ToPrimitive; // For Int64 conversion
use thiserror::Error;
use log::error; // Assuming logger is set up

// Maximum number of parts allowed in a commitment built using the builder.
const PARTS_CAP: usize = 3;
// Maximum allowed size (number of BigInts) for a single part.
const MAX_PART_SIZE: i64 = 1 * 1024 * 1024; // 1 Mi BigInts (liberal, as in Go code)

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BuilderError {
    #[error("too many commitment parts: got {0}, max {PARTS_CAP}")]
    TooManyParts(usize),
    #[error("commitment part too large: part index {0}, size {1}, max {MAX_PART_SIZE}")]
    PartTooLarge(usize, i64),
    #[error("secrets data is nil or too small")]
    SecretsNilOrTooSmall,
    #[error("element index overflow during parsing")]
    ElementOverflow,
    #[error("not enough data in secrets to consume the stated part length")]
    NotEnoughData,
    #[error("failed to convert length prefix to i64")]
    LengthConversionError,
}

/// A builder helper for constructing the `secrets` part of a `HashCommitDecommit`.
/// It allows adding multiple "parts" (slices of BigInts).
/// The final `secrets` Vec is structured as: `[len1, part1..., len2, part2..., ...]`, where `lenX` is the number of elements in `partX`.
#[derive(Debug, Clone, Default)]
pub struct CommitmentBuilder {
    parts: Vec<Vec<BigInt>>,
}

impl CommitmentBuilder {
    /// Creates a new, empty builder with a default capacity.
    pub fn new() -> Self {
        Self {
            parts: Vec::with_capacity(PARTS_CAP),
        }
    }

    /// Returns a slice of the parts currently added to the builder.
    pub fn parts(&self) -> &[Vec<BigInt>] {
        &self.parts
    }

    /// Adds a new part (a slice of BigInts) to the builder.
    /// Clones the data from the input slice.
    pub fn add_part(&mut self, part: &[BigInt]) -> &mut Self {
        self.parts.push(part.to_vec());
        self
    }

    /// Consolidates the added parts into a single `secrets` vector suitable for commitment.
    /// The format is `[len1, part1..., len2, part2..., ...]`, where `lenX` is the length of `partX`.
    /// Returns an error if the number of parts exceeds `PARTS_CAP` or if any part exceeds `MAX_PART_SIZE`.
    pub fn secrets(&self) -> Result<Vec<BigInt>, BuilderError> {
        if self.parts.len() > PARTS_CAP {
            return Err(BuilderError::TooManyParts(self.parts.len()));
        }

        let mut secrets_len_estimate = 0;
        for part in &self.parts {
            secrets_len_estimate += 1 + part.len(); // +1 for length prefix
        }

        let mut secrets = Vec::with_capacity(secrets_len_estimate);
        for (i, part) in self.parts.iter().enumerate() {
            let part_len = part.len() as i64;
            if part_len > MAX_PART_SIZE {
                return Err(BuilderError::PartTooLarge(i, part_len));
            }
            // Add length prefix
            secrets.push(BigInt::from(part_len));
            // Add part elements
            secrets.extend_from_slice(part);
        }
        Ok(secrets)
    }

    /// Parses a `secrets` vector (in the format `[len1, part1..., len2, part2...]`)
    /// back into a Vec of its constituent parts.
    /// Returns an error if the format is invalid, parts are too large, or exceed capacity.
    pub fn parse_secrets(secrets: &[BigInt]) -> Result<Vec<Vec<BigInt>>, BuilderError> {
        if secrets.len() < 2 { // Must have at least length + one element
            return Err(BuilderError::SecretsNilOrTooSmall);
        }

        let mut parts = Vec::with_capacity(PARTS_CAP);
        let mut current_index: usize = 0;

        while current_index < secrets.len() {
            // Read length prefix
            let len_prefix = secrets.get(current_index)
                .ok_or(BuilderError::NotEnoughData)?;
            let next_part_len = len_prefix.to_i64()
                 .ok_or(BuilderError::LengthConversionError)?;

            if next_part_len < 0 {
                 error!("ParseSecrets: Invalid negative part length encountered: {}", next_part_len);
                 return Err(BuilderError::PartTooLarge(parts.len(), next_part_len)); // Treat negative as invalid size
             }
            if next_part_len > MAX_PART_SIZE {
                return Err(BuilderError::PartTooLarge(parts.len(), next_part_len));
            }

            let next_part_len_usize = next_part_len as usize;
            current_index += 1; // Move past the length prefix

            // Check if capacity exceeded
            if parts.len() >= PARTS_CAP {
                return Err(BuilderError::TooManyParts(parts.len() + 1));
            }

            // Check if enough elements remain for the part
            let end_index = current_index.checked_add(next_part_len_usize)
                .ok_or(BuilderError::ElementOverflow)?; // Check for usize overflow

            if end_index > secrets.len() {
                return Err(BuilderError::NotEnoughData);
            }

            // Extract the part
            let part = secrets[current_index..end_index].to_vec();
            parts.push(part);

            // Update index for the next iteration
            current_index = end_index;
        }

        Ok(parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint_dig::{BigInt, Num};

    #[test]
    fn test_builder_secrets_and_parse() {
        let mut builder = CommitmentBuilder::new();

        let part1 = vec![BigInt::from(10), BigInt::from(20)];
        let part2 = vec![BigInt::from(30)];
        let part3 = vec![
            BigInt::parse_bytes(b"1111", 10).unwrap(),
            BigInt::parse_bytes(b"2222", 10).unwrap(),
            BigInt::parse_bytes(b"3333", 10).unwrap(),
        ];

        builder.add_part(&part1);
        builder.add_part(&part2);
        builder.add_part(&part3);

        assert_eq!(builder.parts().len(), 3);

        // Build secrets
        let secrets = builder.secrets().expect("Building secrets failed");

        // Expected format: [len1, p1_1, p1_2, len2, p2_1, len3, p3_1, p3_2, p3_3]
        // lengths: 2, 1, 3
        // total elements: 1 + 2 + 1 + 1 + 1 + 3 = 9
        assert_eq!(secrets.len(), 9);
        assert_eq!(secrets[0], BigInt::from(2)); // len1
        assert_eq!(secrets[1], part1[0]);
        assert_eq!(secrets[2], part1[1]);
        assert_eq!(secrets[3], BigInt::from(1)); // len2
        assert_eq!(secrets[4], part2[0]);
        assert_eq!(secrets[5], BigInt::from(3)); // len3
        assert_eq!(secrets[6], part3[0]);
        assert_eq!(secrets[7], part3[1]);
        assert_eq!(secrets[8], part3[2]);

        // Parse secrets back
        let parsed_parts = CommitmentBuilder::parse_secrets(&secrets).expect("Parsing secrets failed");

        assert_eq!(parsed_parts.len(), 3);
        assert_eq!(parsed_parts[0], part1);
        assert_eq!(parsed_parts[1], part2);
        assert_eq!(parsed_parts[2], part3);
    }

    #[test]
    fn test_builder_limits() {
        let mut builder = CommitmentBuilder::new();
        let part = vec![BigInt::one()];

        // Add parts up to capacity
        for _ in 0..PARTS_CAP {
            builder.add_part(&part);
        }
        assert!(builder.secrets().is_ok());

        // Add one more part - should fail
        builder.add_part(&part);
        assert!(matches!(builder.secrets(), Err(BuilderError::TooManyParts(_))));

        // Test large part size
        let mut builder_large = CommitmentBuilder::new();
        // Create a part slightly larger than MAX_PART_SIZE
        // Need to convert MAX_PART_SIZE + 1 to usize, handle potential truncation if MAX_PART_SIZE is huge
        let large_part_size = (MAX_PART_SIZE + 1).try_into().unwrap_or(usize::MAX);
         if large_part_size < usize::MAX { // Avoid trying to create impossibly large vec
            let large_part = vec![BigInt::one(); large_part_size];
            builder_large.add_part(&large_part);
            let secrets_result = builder_large.secrets();
             println!("Large part secrets result: {:?}", secrets_result);
            assert!(matches!(secrets_result, Err(BuilderError::PartTooLarge(_, _))));
         } else {
             println!("Skipping large part size test as MAX_PART_SIZE is too large for usize");
         }

    }

    #[test]
    fn test_parse_errors() {
        // Nil/Too small
        assert!(matches!(CommitmentBuilder::parse_secrets(&[]), Err(BuilderError::SecretsNilOrTooSmall)));
        assert!(matches!(CommitmentBuilder::parse_secrets(&[BigInt::one()]), Err(BuilderError::SecretsNilOrTooSmall)));

        // Not enough data for declared length
        let secrets1 = vec![BigInt::from(3), BigInt::one(), BigInt::two()]; // Declares len 3, only 2 elements follow
        assert!(matches!(CommitmentBuilder::parse_secrets(&secrets1), Err(BuilderError::NotEnoughData)));

        // Part too large declared
         let large_len = MAX_PART_SIZE + 1;
         let secrets2 = vec![BigInt::from(large_len), BigInt::one()];
         assert!(matches!(CommitmentBuilder::parse_secrets(&secrets2), Err(BuilderError::PartTooLarge(_, _))));

        // Too many parts encoded
        let secrets3 = vec![
            BigInt::from(1), BigInt::from(10), // Part 1
            BigInt::from(1), BigInt::from(20), // Part 2
            BigInt::from(1), BigInt::from(30), // Part 3
            BigInt::from(1), BigInt::from(40), // Part 4 (exceeds PARTS_CAP=3)
        ];
        assert!(matches!(CommitmentBuilder::parse_secrets(&secrets3), Err(BuilderError::TooManyParts(_))));

         // Missing final part data after length prefix
         let secrets4 = vec![BigInt::from(1), BigInt::from(10), BigInt::from(1)]; // Declares len 1, no element follows
         assert!(matches!(CommitmentBuilder::parse_secrets(&secrets4), Err(BuilderError::NotEnoughData)));
    }

     #[test]
    fn test_parse_empty_part() {
        let mut builder = CommitmentBuilder::new();
        let part1 = vec![BigInt::one()];
        let part2 = vec![]; // Empty part
        let part3 = vec![BigInt::two()];

        builder.add_part(&part1).add_part(&part2).add_part(&part3);
        let secrets = builder.secrets().unwrap();

        // Expected: [1, 1, 0, 1, 2]
        assert_eq!(secrets.len(), 5);
        assert_eq!(secrets[0], BigInt::one());
        assert_eq!(secrets[1], BigInt::one());
        assert_eq!(secrets[2], BigInt::zero()); // Length of empty part
        assert_eq!(secrets[3], BigInt::one());
        assert_eq!(secrets[4], BigInt::two());

        let parsed = CommitmentBuilder::parse_secrets(&secrets).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], part1);
        assert_eq!(parsed[1], part2); // Should be empty vec
        assert!(parsed[1].is_empty());
        assert_eq!(parsed[2], part3);
    }
} 