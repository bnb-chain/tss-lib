// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Zero-knowledge proof of knowledge of the discrete logarithm over safe prime product (DLN proof).
// A proof of knowledge of the discrete log `x` such that `h2 = h1^x mod N`.

// Translation of tss-lib-go/crypto/dlnproof/proof.go

use crate::{
    common::{
        hash::sha512_256i,
        int::{is_in_interval, ModInt},
        random::get_random_positive_int,
        slice::{multi_bytes_to_bigints, bigints_to_bytes},
    },
    crypto::commitments::CommitmentBuilder,
};

use num_bigint_dig::{{BigInt, Sign}};
use num_integer::Integer;
use num_traits::{{Zero, One}};
use rand::{{CryptoRng, RngCore}};
use serde::{{Deserialize, Serialize}};
use thiserror::Error;
use log::error;

/// The number of iterations in the DLN proof.
pub const ITERATIONS: usize = 128;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DlnError {
    #[error("invalid parameters: {0}")]
    InvalidParameters(String),
    #[error("proof verification failed")]
    VerificationFailed,
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("deserialization error: {0}")]
    DeserializationError(String),
    #[error("internal error: {0}")]
    InternalError(String),
}

/// Represents the DLN proof `(α_i, t_i)` for `i` in `[1, ITERATIONS]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
     // Use Vec instead of fixed-size array for easier serialization/deserialization
    #[serde(with = "crate::serde_support::vec_bigint_bytes")]
    pub alpha: Vec<BigInt>,
    #[serde(with = "crate::serde_support::vec_bigint_bytes")]
    pub t: Vec<BigInt>,
}

impl Proof {
    /// Creates a new DLN proof.
    /// Requires `N = P*Q` where `P`, `Q` are safe primes, `P = 2p+1`, `Q = 2q+1`.
    /// Proves knowledge of `x` such that `h2 = h1^x mod N`.
    pub fn new<
        R: CryptoRng + RngCore
    >(
        h1: &BigInt,
        h2: &BigInt,
        x: &BigInt, // The secret exponent
        p: &BigInt, // Safe prime factor p of N
        q: &BigInt, // Safe prime factor q of N
        n: &BigInt, // Modulus N = P*Q
        rng: &mut R,
    ) -> Result<Self, DlnError> {
        if h1.sign() != Sign::Plus || h2.sign() != Sign::Plus || x.sign() == Sign::Minus ||
           p.sign() != Sign::Plus || q.sign() != Sign::Plus || n.sign() != Sign::Plus
        {
            return Err(DlnError::InvalidParameters("Inputs must be positive (except x)".to_string()));
        }

        // TODO: Add primality tests for p, q if necessary, or ensure they are safe primes.

        let p_mul_q = p * q; // phi(N) / 4, or related to the order of the subgroup? Check usage.
                             // In Go code, `p` and `q` are the Sophie Germain primes (p', q'). P=2p+1, Q=2q+1.
                             // So p*q = p'*q'. Random values `a` are mod p'q'.
        let mod_n = ModInt::new(n.clone());
        let mod_pq = ModInt::new(p_mul_q.clone());

        let mut a_vals = Vec::with_capacity(ITERATIONS);
        let mut alpha_vals = Vec::with_capacity(ITERATIONS);

        for _ in 0..ITERATIONS {
            // a_i <- Z_{p*q}
            let a_i = get_random_positive_int(rng, &p_mul_q)
                .ok_or_else(|| DlnError::InternalError("Failed to generate a_i".to_string()))?;
            // alpha_i = h1^{a_i} mod N
            let alpha_i = mod_n.exp(h1, &a_i);
            a_vals.push(a_i);
            alpha_vals.push(alpha_i);
        }

        // c = H(h1, h2, N, alpha_1, ..., alpha_m)
        let mut hash_input: Vec<&BigInt> = Vec::with_capacity(3 + ITERATIONS);
        hash_input.push(h1);
        hash_input.push(h2);
        hash_input.push(n);
        for alpha_i in &alpha_vals {
            hash_input.push(alpha_i);
        }
        let c = sha512_256i(&hash_input)
            .ok_or_else(|| DlnError::InternalError("Failed to compute challenge hash c".to_string()))?;

        let mut t_vals = Vec::with_capacity(ITERATIONS);
        for i in 0..ITERATIONS {
            // c_i = i-th bit of c
            let c_i_bit = if c.test_bit(i as u64) { BigInt::one() } else { BigInt::zero() };

            // t_i = a_i + c_i * x mod (p*q)
            let cix = mod_pq.mul(&c_i_bit, x);
            let t_i = mod_pq.add(&a_vals[i], &cix);
            t_vals.push(t_i);
        }

        Ok(Proof { alpha: alpha_vals, t: t_vals })
    }

    /// Verifies the DLN proof.
    pub fn verify(
        &self,
        h1: &BigInt,
        h2: &BigInt,
        n: &BigInt,
    ) -> bool {
        if self.alpha.len() != ITERATIONS || self.t.len() != ITERATIONS || n.sign() != Sign::Plus {
            error!("DLN Verify: Proof length mismatch or invalid N");
            return false;
        }

        let mod_n = ModInt::new(n.clone());
        let one = BigInt::one();

        // Basic input validation (similar to Go)
        let h1_mod = mod_n.add(h1, &BigInt::zero());
        let h2_mod = mod_n.add(h2, &BigInt::zero());
        if h1_mod <= one || h1_mod >= *n || h2_mod <= one || h2_mod >= *n || h1_mod == h2_mod {
             error!("DLN Verify: Invalid h1/h2 input");
            return false;
        }

        // Recalculate challenge c = H(...)
        let c = {
            let mut hash_input: Vec<&BigInt> = Vec::with_capacity(3 + ITERATIONS);
            hash_input.push(h1);
            hash_input.push(h2);
            hash_input.push(n);
            for alpha_i in &self.alpha {
                // Check alpha_i validity
                let alpha_i_mod = mod_n.add(alpha_i, &BigInt::zero());
                if alpha_i_mod <= one || alpha_i_mod >= *n {
                     error!("DLN Verify: Invalid alpha_i in proof");
                    return false;
                }
                hash_input.push(alpha_i);
            }
            match sha512_256i(&hash_input) {
                 Some(hash) => hash,
                 None => { error!("DLN Verify: Failed to compute challenge hash c"); return false; }
             }
        };

        // Verify check: h1^{t_i} == alpha_i * h2^{c_i} mod N for all i
        for i in 0..ITERATIONS {
            let alpha_i = &self.alpha[i];
            let t_i = &self.t[i];

             // Check t_i validity (similar to Go check)
             let t_i_mod = mod_n.add(t_i, &BigInt::zero());
             if t_i_mod <= one || t_i_mod >= *n {
                 error!("DLN Verify: Invalid t_i in proof");
                 return false;
             }

            // c_i = i-th bit of c
            let c_i_bit = if c.test_bit(i as u64) { BigInt::one() } else { BigInt::zero() };

            // lhs = h1^{t_i} mod N
            let lhs = mod_n.exp(h1, t_i);

            // rhs = alpha_i * h2^{c_i} mod N
            let h2_ci = mod_n.exp(h2, &c_i_bit);
            let rhs = mod_n.mul(alpha_i, &h2_ci);

            if lhs != rhs {
                error!("DLN Verify: Check failed at iteration {}", i);
                return false;
            }
        }

        true
    }

    /// Serializes the proof using the CommitmentBuilder format.
    pub fn serialize(&self) -> Result<Vec<Vec<u8>>, DlnError> {
        let mut builder = CommitmentBuilder::new();
        builder.add_part(&self.alpha); // Add alpha vector as first part
        builder.add_part(&self.t);     // Add t vector as second part

        let secrets = builder.secrets().map_err(|e| DlnError::SerializationError(e.to_string()))?;
        let secrets_ref: Vec<&BigInt> = secrets.iter().collect();
        Ok(bigints_to_bytes(&secrets_ref))
    }

    /// Deserializes the proof from the CommitmentBuilder format.
    pub fn deserialize(bzs: &[Vec<u8>]) -> Result<Self, DlnError> {
        let secrets = multi_bytes_to_bigints(bzs);
        let parsed_parts = CommitmentBuilder::parse_secrets(&secrets)
            .map_err(|e| DlnError::DeserializationError(e.to_string()))?;

        if parsed_parts.len() != 2 {
            return Err(DlnError::DeserializationError(format!(
                "Expected 2 parts, got {}", parsed_parts.len()
            )));
        }
        if parsed_parts[0].len() != ITERATIONS {
             return Err(DlnError::DeserializationError(format!(
                "Expected alpha part length {}, got {}", ITERATIONS, parsed_parts[0].len()
            )));
        }
        if parsed_parts[1].len() != ITERATIONS {
             return Err(DlnError::DeserializationError(format!(
                "Expected t part length {}, got {}", ITERATIONS, parsed_parts[1].len()
            )));
        }

        Ok(Proof {
            alpha: parsed_parts[0].clone(),
            t: parsed_parts[1].clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::safe_prime::get_safe_prime_details;
    use rand::thread_rng;

    #[test]
    fn test_dln_proof_create_verify() {
        let mut rng = thread_rng();

        // Setup N, P, Q, p, q (using safe primes)
        // Using small primes for testing speed.
        // P = 2p+1, Q = 2q+1, N = P*Q
        let safe_p = get_safe_prime_details(64, 1, &mut rng).unwrap();
        let safe_q = get_safe_prime_details(64, 1, &mut rng).unwrap();
        let p_prime = safe_p.p_prime(); // p'
        let q_prime = safe_q.q_prime(); // q'
        let p_safe = safe_p.safe_prime(); // P
        let q_safe = safe_q.safe_prime(); // Q
        let n = p_safe * q_safe; // N

        // Setup h1, h2, x
        // h1 should be a generator of QR_N ? Or just random?
        // Let h1 = random in Z*_N
        let h1 = get_random_positive_int(&mut rng, &n).unwrap(); // Simplification
        let x = get_random_positive_int(&mut rng, &(p_prime * q_prime)).unwrap(); // Secret x in Z_{p'q'}
        let mod_n = ModInt::new(n.clone());
        let h2 = mod_n.exp(&h1, &x); // h2 = h1^x mod N

        // Ensure h1, h2 are valid and distinct
        assert!(h1 > BigInt::one() && h1 < n);
        assert!(h2 > BigInt::one() && h2 < n);
        assert_ne!(h1, h2);

        println!("N: ...{}", n.to_string().chars().take(10).collect::<String>());
        println!("p': {}", p_prime);
        println!("q': {}", q_prime);
        println!("h1: ...{}", h1.to_string().chars().take(10).collect::<String>());
        println!("h2: ...{}", h2.to_string().chars().take(10).collect::<String>());
        println!("x: {}", x);

        // 1. Create Proof
        let proof = Proof::new(&h1, &h2, &x, p_prime, q_prime, &n, &mut rng)
            .expect("Proof generation failed");

        assert_eq!(proof.alpha.len(), ITERATIONS);
        assert_eq!(proof.t.len(), ITERATIONS);

        // 2. Verify Proof
        let is_valid = proof.verify(&h1, &h2, &n);
        assert!(is_valid, "Proof verification failed");

        // 3. Test verification failure: wrong h1
        let h1_wrong = &h1 + BigInt::one();
        assert!(!proof.verify(&h1_wrong, &h2, &n), "Proof verified with wrong h1");

        // 4. Test verification failure: wrong h2
        let h2_wrong = &h2 + BigInt::one();
        assert!(!proof.verify(&h1, &h2_wrong, &n), "Proof verified with wrong h2");

        // 5. Test verification failure: wrong N
        let n_wrong = &n + BigInt::one();
        assert!(!proof.verify(&h1, &h2, &n_wrong), "Proof verified with wrong N");

        // 6. Test verification failure: tampered alpha
        let mut tampered_alpha_proof = proof.clone();
        tampered_alpha_proof.alpha[0] += BigInt::one();
        assert!(!tampered_alpha_proof.verify(&h1, &h2, &n), "Proof verified with tampered alpha");

         // 7. Test verification failure: tampered t
        let mut tampered_t_proof = proof.clone();
        tampered_t_proof.t[0] += BigInt::one();
        assert!(!tampered_t_proof.verify(&h1, &h2, &n), "Proof verified with tampered t");
    }

     #[test]
    fn test_dln_proof_serialization() {
        let mut rng = thread_rng();
        let safe_p = get_safe_prime_details(64, 1, &mut rng).unwrap();
        let safe_q = get_safe_prime_details(64, 1, &mut rng).unwrap();
        let p_prime = safe_p.p_prime();
        let q_prime = safe_q.q_prime();
        let p_safe = safe_p.safe_prime();
        let q_safe = safe_q.safe_prime();
        let n = p_safe * q_safe;
        let h1 = get_random_positive_int(&mut rng, &n).unwrap();
        let x = get_random_positive_int(&mut rng, &(p_prime * q_prime)).unwrap();
        let mod_n = ModInt::new(n.clone());
        let h2 = mod_n.exp(&h1, &x);

        let proof = Proof::new(&h1, &h2, &x, p_prime, q_prime, &n, &mut rng).unwrap();

        // Serialize
        let bzs = proof.serialize().expect("Serialization failed");

        // Check byte format (should have length prefixes encoded by builder)
         // Example: [len(alpha), alpha_1, ..., alpha_m, len(t), t_1, ..., t_m]
         // So, total BigInts = 2 + 2 * ITERATIONS
         let secrets_check = multi_bytes_to_bigints(&bzs);
         assert_eq!(secrets_check.len(), 2 + 2 * ITERATIONS);
         assert_eq!(secrets_check[0], BigInt::from(ITERATIONS)); // Length of alpha
         assert_eq!(secrets_check[1 + ITERATIONS], BigInt::from(ITERATIONS)); // Length of t

        // Deserialize
        let proof_deserialized = Proof::deserialize(&bzs).expect("Deserialization failed");

        assert_eq!(proof, proof_deserialized, "Deserialized proof mismatch");

         // Verify deserialized proof
         assert!(proof_deserialized.verify(&h1, &h2, &n), "Deserialized proof failed verification");
     }

      #[test]
     fn test_dln_proof_deserialize_errors() {
         // Too few parts
         let mut builder1 = CommitmentBuilder::new();
         builder1.add_part(&[BigInt::one()]); // Only one part
         let secrets1 = builder1.secrets().unwrap();
         let secrets_ref1: Vec<&BigInt> = secrets1.iter().collect();
         let bzs1 = bigints_to_bytes(&secrets_ref1);
         assert!(matches!(Proof::deserialize(&bzs1), Err(DlnError::DeserializationError(_))));

         // Too many parts
         let mut builder3 = CommitmentBuilder::new();
         builder3.add_part(&vec![BigInt::one(); ITERATIONS]);
         builder3.add_part(&vec![BigInt::one(); ITERATIONS]);
         builder3.add_part(&[BigInt::one()]); // Third part
         let secrets3 = builder3.secrets().unwrap();
         let secrets_ref3: Vec<&BigInt> = secrets3.iter().collect();
         let bzs3 = bigints_to_bytes(&secrets_ref3);
         assert!(matches!(Proof::deserialize(&bzs3), Err(DlnError::DeserializationError(_))));

          // Incorrect length for alpha
         let mut builder_len_a = CommitmentBuilder::new();
         builder_len_a.add_part(&vec![BigInt::one(); ITERATIONS - 1]); // Wrong length
         builder_len_a.add_part(&vec![BigInt::one(); ITERATIONS]);
         let secrets_len_a = builder_len_a.secrets().unwrap();
         let secrets_ref_len_a: Vec<&BigInt> = secrets_len_a.iter().collect();
         let bzs_len_a = bigints_to_bytes(&secrets_ref_len_a);
         assert!(matches!(Proof::deserialize(&bzs_len_a), Err(DlnError::DeserializationError(_))));

          // Incorrect length for t
         let mut builder_len_t = CommitmentBuilder::new();
         builder_len_t.add_part(&vec![BigInt::one(); ITERATIONS]);
         builder_len_t.add_part(&vec![BigInt::one(); ITERATIONS + 1]); // Wrong length
         let secrets_len_t = builder_len_t.secrets().unwrap();
         let secrets_ref_len_t: Vec<&BigInt> = secrets_len_t.iter().collect();
         let bzs_len_t = bigints_to_bytes(&secrets_ref_len_t);
         assert!(matches!(Proof::deserialize(&bzs_len_t), Err(DlnError::DeserializationError(_))));
     }
} 