// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/crypto/commitments/commitment.go
// Original Go version partly ported from:
// https://github.com/KZen-networks/curv/blob/78a70f43f5eda376e5888ce33aec18962f572bbe/src/cryptographic_primitives/commitments/hash_commitment.rs

use crate::common::{
    hash::sha512_256i,
    random::must_get_random_int,
    slice::multi_bytes_to_bigints,
};
use num_bigint_dig::BigInt;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

// Using 256 bits (32 bytes) for the random value in the commitment,
// aligning with the output size of SHA512_256.
const HASH_COMMITMENT_RANDOMNESS_BITS: usize = 256;

// Type aliases for clarity
pub type HashCommitment = BigInt;
// Decommitment includes the randomness `r` followed by the secrets.
pub type HashDeCommitment = Vec<BigInt>;

/// Represents a Pedersen Hash Commitment C = H(r, m1, m2, ...).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashCommitDecommit {
    #[serde(rename = "c")]
    pub c: HashCommitment,
    #[serde(rename = "d")]
    pub d: HashDeCommitment,
}

impl HashCommitDecommit {
    /// Creates a new commitment C = H(r, secrets...) using the provided randomness `r`.
    pub fn new_with_randomness(r: BigInt, secrets: &[&BigInt]) -> Self {
        let mut parts: Vec<&BigInt> = Vec::with_capacity(secrets.len() + 1);
        parts.push(&r); // Add randomness first
        parts.extend_from_slice(secrets);

        // Commit: H(r, secret1, secret2, ...)
        let commitment = sha512_256i(&parts).expect("Hashing failed during commitment generation");

        // Decommitment = [r, secret1, secret2, ...]
        let mut decommitment_vec: Vec<BigInt> = Vec::with_capacity(parts.len());
        decommitment_vec.push(r); // Store owned randomness
        for &secret in secrets {
            decommitment_vec.push(secret.clone()); // Store owned secrets
        }

        Self {
            c: commitment,
            d: decommitment_vec,
        }
    }

    /// Creates a new commitment C = H(r, secrets...) generating secure randomness `r` internally.
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R, secrets: &[&BigInt]) -> Self {
        let r = must_get_random_int(rng, HASH_COMMITMENT_RANDOMNESS_BITS);
        Self::new_with_randomness(r, secrets)
    }

    /// Creates the decommitment part from marshalled byte slices.
    pub fn decommitment_from_bytes(marshalled: &[Vec<u8>]) -> HashDeCommitment {
        multi_bytes_to_bigints(marshalled)
    }

    /// Verifies if the commitment `C` matches the hash of the decommitment values `D`.
    pub fn verify(&self) -> bool {
        // Check if D is empty (should at least contain randomness r)
        if self.d.is_empty() {
            return false;
        }
        // Re-calculate hash H(D[0], D[1], ...)
        let d_refs: Vec<&BigInt> = self.d.iter().collect();
        let calculated_hash = sha512_256i(&d_refs);

        match calculated_hash {
            Some(hash) => hash == self.c,
            None => false, // Hashing failed (e.g., if d_refs was somehow empty despite check)
        }
    }

    /// Verifies the commitment and, if successful, returns the original secrets.
    /// The secrets are the decommitment values excluding the first element (the randomness `r`).
    /// Returns `(true, secrets)` on success, `(false, empty_vec)` on failure.
    pub fn decommit(&self) -> (bool, Vec<BigInt>) {
        if self.verify() {
            // Skip the first element (randomness `r`) and return clones of the secrets
            let secrets = self.d.iter().skip(1).cloned().collect();
            (true, secrets)
        } else {
            (false, Vec::new()) // Return empty vector on failure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::slice::bigints_to_bytes;
    use num_bigint_dig::{Num, BigInt};
    use rand::thread_rng;

    #[test]
    fn test_hash_commitment_verify_decommit() {
        let mut rng = thread_rng();
        let secret1 = BigInt::from(123456789u64);
        let secret2 = BigInt::parse_bytes(b"deadbeefcafebabe", 16).unwrap();
        let secrets = vec![&secret1, &secret2];

        // 1. Create commitment
        let commit_decommit = HashCommitDecommit::new(&mut rng, &secrets);
        println!("Commitment: {}", commit_decommit.c.to_str_radix(16));
        println!("Decommitment (r, s1, s2): {:?}", commit_decommit.d);

        // 2. Verify
        assert!(commit_decommit.verify(), "Commitment verification failed");

        // 3. Decommit
        let (success, revealed_secrets) = commit_decommit.decommit();
        assert!(success, "Decommitment failed");
        assert_eq!(revealed_secrets.len(), secrets.len());
        assert_eq!(revealed_secrets[0], secret1);
        assert_eq!(revealed_secrets[1], secret2);

        // 4. Test verification failure (tamper with commitment)
        let mut tampered_commit = commit_decommit.clone();
        tampered_commit.c += BigInt::one();
        assert!(!tampered_commit.verify(), "Tampered commitment verified successfully");
        let (fail_success, _) = tampered_commit.decommit();
        assert!(!fail_success, "Decommit succeeded on tampered commitment");

        // 5. Test verification failure (tamper with decommitment - randomness)
        let mut tampered_decommit_r = commit_decommit.clone();
        if !tampered_decommit_r.d.is_empty() {
            tampered_decommit_r.d[0] += BigInt::one();
            assert!(!tampered_decommit_r.verify(), "Tampered decommitment (r) verified");
            let (fail_success_r, _) = tampered_decommit_r.decommit();
            assert!(!fail_success_r, "Decommit succeeded on tampered decommitment (r)");
        }

         // 6. Test verification failure (tamper with decommitment - secret)
        let mut tampered_decommit_s = commit_decommit.clone();
        if tampered_decommit_s.d.len() > 1 {
            tampered_decommit_s.d[1] += BigInt::one();
            assert!(!tampered_decommit_s.verify(), "Tampered decommitment (s) verified");
            let (fail_success_s, _) = tampered_decommit_s.decommit();
            assert!(!fail_success_s, "Decommit succeeded on tampered decommitment (s)");
        }
    }

    #[test]
    fn test_new_with_randomness() {
        let secret1 = BigInt::from(999u64);
        let secrets = vec![&secret1];
        let r = BigInt::from(123u64);

        let commit_decommit = HashCommitDecommit::new_with_randomness(r.clone(), &secrets);

        // Verify that the provided randomness is the first element in D
        assert_eq!(commit_decommit.d.len(), 2);
        assert_eq!(commit_decommit.d[0], r);
        assert_eq!(commit_decommit.d[1], secret1);

        // Verify correctness
        assert!(commit_decommit.verify());
        let (success, revealed) = commit_decommit.decommit();
        assert!(success);
        assert_eq!(revealed.len(), 1);
        assert_eq!(revealed[0], secret1);
    }

    #[test]
    fn test_decommitment_from_bytes() {
        let r = BigInt::from(111u64);
        let s1 = BigInt::from(222u64);
        let s2 = BigInt::from(333u64);
        let original_d = vec![r, s1, s2];

        let d_refs: Vec<&BigInt> = original_d.iter().collect();
        let marshalled = bigints_to_bytes(&d_refs);

        let reconstructed_d = HashCommitDecommit::decommitment_from_bytes(&marshalled);

        assert_eq!(reconstructed_d, original_d);
    }

    #[test]
    fn test_empty_secrets() {
        let mut rng = thread_rng();
        let secrets: Vec<&BigInt> = Vec::new();

        let commit_decommit = HashCommitDecommit::new(&mut rng, &secrets);

        assert_eq!(commit_decommit.d.len(), 1); // Should only contain randomness 'r'
        assert!(commit_decommit.verify());

        let (success, revealed_secrets) = commit_decommit.decommit();
        assert!(success);
        assert!(revealed_secrets.is_empty());
    }

    #[test]
    fn test_serde_serialization() {
         let mut rng = thread_rng();
        let secret1 = BigInt::from(123u64);
        let secrets = vec![&secret1];
        let commit_decommit = HashCommitDecommit::new(&mut rng, &secrets);

        let serialized = serde_json::to_string(&commit_decommit).unwrap();
        println!("Serialized: {}", serialized);

        let deserialized: HashCommitDecommit = serde_json::from_str(&serialized).unwrap();

        assert_eq!(commit_decommit, deserialized);
        assert!(deserialized.verify());
    }
} 