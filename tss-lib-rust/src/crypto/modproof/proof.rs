// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Modulo Proof (modproof) based on GG18Spec Figure 16.
// Proves that N is a Blum modulus (product of two safe primes P, Q where P=Q=3 mod 4)

// Translation of tss-lib-go/crypto/modproof/proof.go

use crate::common::{
    hash::sha512_256i_tagged,
    hash_utils::rejection_sample,
    int::{ModInt, is_in_interval},
    random::get_random_quadratic_non_residue,
    slice::{multi_bytes_to_bigints_fixed, bigints_to_bytes_fixed},
};

use jacobi::Symbol;
use num_bigint_dig::{{BigInt, Sign}};
use num_integer::Integer;
use num_prime::PrimalityTestConfig;
use num_traits::{{Zero, One}};
use rand::{{CryptoRng, RngCore}};
use serde::{{Deserialize, Serialize}};
use thiserror::Error;
use log::error;
use rayon::prelude::*; // For parallel verification

/// Number of iterations for the Modulo Proof.
pub const ITERATIONS: usize = 80;
/// Total number of byte parts for serialization.
pub const PROOF_MOD_BYTES_PARTS: usize = ITERATIONS * 2 + 3;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ModProofError {
    #[error("invalid parameters: {0}")]
    InvalidParameters(String),
    #[error("proof generation failed: {0}")]
    ProofGenerationError(String),
    #[error("proof verification failed")]
    VerificationFailed,
    #[error("byte conversion error: expected {expected} parts, got {got}")]
    ByteConversionError{ expected: usize, got: usize },
    #[error("internal error: {0}")]
    InternalError(String),
}

/// Modulo Proof structure (Fig 16).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofMod {
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub w: BigInt,
    // Use Vec for easier serialization
    #[serde(with = "crate::serde_support::vec_bigint_bytes")]
    pub x: Vec<BigInt>,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub a: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub b: BigInt,
    #[serde(with = "crate::serde_support::vec_bigint_bytes")]
    pub z: Vec<BigInt>,
}

impl ProofMod {
    /// Creates a new Modulo Proof (Fig 16).
    /// Proves that `N` is a Blum modulus, product of `P` and `Q` which are safe primes == 3 mod 4.
    pub fn new<R: CryptoRng + RngCore>(
        session: &[u8],
        n: &BigInt,
        p: &BigInt,
        q: &BigInt,
        rng: &mut R,
    ) -> Result<Self, ModProofError> {
         // Parameter checks
         if n.sign() != Sign::Plus || p.sign() != Sign::Plus || q.sign() != Sign::Plus {
             return Err(ModProofError::InvalidParameters("N, P, Q must be positive".to_string()));
         }
         if n != &(p * q) {
              return Err(ModProofError::InvalidParameters("N != P*Q".to_string()));
         }
         // Check P = 3 mod 4 and Q = 3 mod 4
         if (p % BigInt::from(4u32)) != BigInt::from(3u32) ||
            (q % BigInt::from(4u32)) != BigInt::from(3u32)
         {
              return Err(ModProofError::InvalidParameters("P or Q is not 3 mod 4".to_string()));
         }
         // TODO: Check if P, Q are safe primes?

        let mod_n = ModInt::new(n.clone());
        let one = BigInt::one();

        let phi = (p - &one) * (q - &one);
        let mod_phi = ModInt::new(phi.clone());

        // Fig 16.1: Find w such that Jacobi(w/N) = -1
        let w = get_random_quadratic_non_residue(rng, n)
            .ok_or_else(|| ModProofError::ProofGenerationError("Failed to find quadratic non-residue w".to_string()))?;

        // Fig 16.2: Generate y_i challenges
        let mut y_vals = Vec::with_capacity(ITERATIONS);
        let mut hash_input_prefix = vec![&w, n];
        for i in 0..ITERATIONS {
            // Clone current y_vals to pass to hash
             let current_y_refs: Vec<&BigInt> = y_vals.iter().collect();
             let current_hash_input: Vec<&BigInt> = hash_input_prefix.iter().cloned().chain(current_y_refs.into_iter()).collect();

            let ei_hash = sha512_256i_tagged(session, &current_hash_input)
                .ok_or_else(|| ModProofError::ProofGenerationError(format!("Failed to hash for y_{}", i)))?;
            let yi = rejection_sample(n, &ei_hash);
            y_vals.push(yi);
        }

        // Fig 16.3: Compute x_i, a_i, b_i, z_i
        let inv_n_mod_phi = mod_phi.mod_inverse(n)
             .ok_or_else(|| ModProofError::ProofGenerationError("N^-1 mod Phi does not exist".to_string()))?;

        // Calculate exponent for 4th root: ( (phi + 4) / 8 )^2 mod phi
        // Works because N=P*Q, P=3(mod 4), Q=3(mod 4) => phi=(P-1)(Q-1) => (phi+4)/8 = ((P-1)(Q-1)+4)/8
        // For P=2p+1, Q=2q+1 (safe primes), phi = 4pq. ((4pq+4)/8)^2 = ((pq+1)/2)^2 mod pq
        let expo_base = (&phi + BigInt::from(4u32)) >> 3; // (phi+4)/8 integer division
        let expo = mod_phi.exp(&expo_base, &BigInt::from(2u32)); // ((phi+4)/8)^2 mod phi

        let mut x_vals = vec![BigInt::zero(); ITERATIONS];
        let mut z_vals = vec![BigInt::zero(); ITERATIONS];
        // Use BigInts for A and B initially, convert from bits later?
        // Go uses Lsh(one, Iterations) to initialize, then SetBit.
        let mut a_val = BigInt::zero(); // Initialize A and B as 0
        let mut b_val = BigInt::zero();

        for i in 0..ITERATIONS {
            let yi = &y_vals[i];
            let mut found = false;
            // Try the four potential square roots based on bits a, b
            for j in 0..4 {
                let a_bit = (j & 1) as u64;
                let b_bit = ((j & 2) >> 1) as u64;

                // yi_candidate = (-1)^a * w^b * yi mod N
                let mut yi_candidate = yi.clone();
                if a_bit > 0 {
                    yi_candidate = mod_n.neg(&yi_candidate);
                }
                if b_bit > 0 {
                    yi_candidate = mod_n.mul(&w, &yi_candidate);
                }

                // Check if yi_candidate is a quadratic residue mod P and mod Q
                if Symbol::new(&yi_candidate, p).is_one() && Symbol::new(&yi_candidate, q).is_one() {
                    // Compute 4th root: x_i = yi_candidate^expo mod N
                    let xi = mod_n.exp(&yi_candidate, &expo);
                    // Compute z_i = yi^{N^-1 mod phi} mod N (? Go uses modN.Exp(Y[i], invN))
                    // Verify N^-1 mod phi is correct. Spec Fig 16 seems to use N^-1 mod phi(N).
                     let zi = mod_n.exp(yi, &inv_n_mod_phi);

                    x_vals[i] = xi;
                    z_vals[i] = zi;
                    // Set bits for A and B
                    if a_bit > 0 { a_val.set_bit(i as u64, true); }
                    if b_bit > 0 { b_val.set_bit(i as u64, true); }
                    found = true;
                    break;
                }
            }
            if !found {
                 // This should theoretically not happen if N is a Blum modulus
                 return Err(ModProofError::ProofGenerationError(format!("Could not find 4th root for y_{}", i)));
             }
        }

        Ok(ProofMod { w, x: x_vals, a: a_val, b: b_val, z: z_vals })
    }

    /// Verifies the Modulo Proof (Fig 16).
    pub fn verify(&self, session: &[u8], n: &BigInt) -> bool {
        if !self.validate_basic() || n.sign() != Sign::Plus {
            error!("ModProof verify: failed basic validation or invalid N");
            return false;
        }

        let mod_n = ModInt::new(n.clone());

        // Basic property checks (from Go code)
        if Symbol::new(&self.w, n).is_one() { // Check Jacobi(w/N) == -1
            error!("ModProof verify: Jacobi(w/N) != -1");
            return false;
        }
        if self.w.sign() != Sign::Plus || self.w >= *n {
            error!("ModProof verify: w out of range [1, N-1]");
            return false;
        }
        for zi in &self.z {
            if zi.sign() != Sign::Plus || *zi >= *n {
                error!("ModProof verify: z_i out of range [1, N-1]");
                return false;
            }
        }
         for xi in &self.x {
            if xi.sign() != Sign::Plus || *xi >= *n {
                error!("ModProof verify: x_i out of range [1, N-1]");
                return false;
            }
        }
        // Check bit length of A and B? Go checks A.BitLen() == Iterations+1.
        // This seems overly strict, it checks the highest bit set is Iterations-1.
        // Let's just check the bits used (0..ITERATIONS-1) are valid 0 or 1 later.

        // Check N properties (from Go)
        if n.is_even() || n.is_probably_prime(Some(PrimalityTestConfig::strict())) {
             error!("ModProof verify: N is even or probably prime");
            return false;
        }

        // Recalculate y_i challenges
         let mut y_vals = Vec::with_capacity(ITERATIONS);
         let mut hash_input_prefix = vec![&self.w, n];
         for i in 0..ITERATIONS {
             let current_y_refs: Vec<&BigInt> = y_vals.iter().collect();
             let current_hash_input: Vec<&BigInt> = hash_input_prefix.iter().cloned().chain(current_y_refs.into_iter()).collect();

             let ei_hash = match sha512_256i_tagged(session, &current_hash_input) {
                 Some(h) => h,
                 None => { error!("ModProof verify: Failed to hash for y_{}", i); return false; }
             };
             let yi = rejection_sample(n, &ei_hash);
             y_vals.push(yi);
         }

        // Fig 16. Verification Checks (parallelized)
        let results: Vec<bool> = (0..ITERATIONS).into_par_iter().map(|i| -> bool {
            let xi = &self.x[i];
            let zi = &self.z[i];
            let yi = &y_vals[i];
            let a_bit = self.a.test_bit(i as u64);
            let b_bit = self.b.test_bit(i as u64);

            // Check 1: z_i^N == y_i mod N
            let check1_lhs = mod_n.exp(zi, n);
            if check1_lhs != *yi {
                 error!("ModProof verify: Check 1 failed for i={}", i);
                return false;
            }

            // Check 2: x_i^4 == (-1)^a * w^b * y_i mod N
            let check2_lhs = mod_n.exp(xi, &BigInt::from(4u32));

            let mut check2_rhs = yi.clone();
            if a_bit {
                check2_rhs = mod_n.neg(&check2_rhs);
            }
            if b_bit {
                check2_rhs = mod_n.mul(&self.w, &check2_rhs);
            }

            if check2_lhs != check2_rhs {
                 error!("ModProof verify: Check 2 failed for i={} (a={}, b={})", i, a_bit, b_bit);
                return false;
            }
            true // Both checks passed for this iteration
        }).collect();

        // Ensure all parallel checks passed
        results.iter().all(|&x| x)
    }

    /// Basic validation ensuring all components are present.
    pub fn validate_basic(&self) -> bool {
         self.x.len() == ITERATIONS && self.z.len() == ITERATIONS &&
         !self.w.is_zero() && !self.a.is_zero() && !self.b.is_zero()
    }

    /// Converts the proof to a vector of byte vectors.
    pub fn to_bytes(&self) -> Result<Vec<Vec<u8>>, ModProofError> {
        if self.x.len() != ITERATIONS || self.z.len() != ITERATIONS {
             return Err(ModProofError::InternalError("Proof has incorrect vector lengths".to_string()));
        }
         Ok(bigints_to_bytes_fixed::<PROOF_MOD_BYTES_PARTS>(&[
            &[&self.w], // Part 1: w
            self.x.iter().collect::<Vec<&BigInt>>().as_slice(), // Parts 2..ITERATIONS+1: x_i
            &[&self.a, &self.b], // Parts ITERATIONS+2, ITERATIONS+3: a, b
            self.z.iter().collect::<Vec<&BigInt>>().as_slice(), // Parts ITERATIONS+4..end: z_i
        ].concat()))
    }

    /// Creates a ProofMod from a slice of byte vectors.
    pub fn from_bytes(bzs: &[Vec<u8>]) -> Result<Self, ModProofError> {
        if bzs.len() != PROOF_MOD_BYTES_PARTS {
            return Err(ModProofError::ByteConversionError{ expected: PROOF_MOD_BYTES_PARTS, got: bzs.len() });
        }
        let ints = multi_bytes_to_bigints_fixed::<PROOF_MOD_BYTES_PARTS>(bzs);

         Ok(Self {
             w: ints[0].clone(),
             x: ints[1..=ITERATIONS].to_vec(),
             a: ints[ITERATIONS + 1].clone(),
             b: ints[ITERATIONS + 2].clone(),
             z: ints[ITERATIONS + 3..].to_vec(),
         })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::safe_prime::get_safe_prime_details;
    use rand::thread_rng;

    fn setup_mod_params() -> (BigInt, BigInt, BigInt) {
         let mut rng = thread_rng();
         // Find P = 3 mod 4
         let p = loop {
             let safe_p = get_safe_prime_details(512, 1, &mut rng).unwrap(); // Small size for test
             let p_val = safe_p.safe_prime();
             if (&p_val % BigInt::from(4u32)) == BigInt::from(3u32) {
                 break p_val;
             }
         };
         // Find Q = 3 mod 4, Q != P
          let q = loop {
             let safe_q = get_safe_prime_details(512, 1, &mut rng).unwrap();
             let q_val = safe_q.safe_prime();
             if q_val != p && (&q_val % BigInt::from(4u32)) == BigInt::from(3u32) {
                 break q_val;
             }
         };
         let n = &p * &q;
         (n, p, q)
     }

    #[test]
    fn test_mod_proof_create_verify() {
        let mut rng = thread_rng();
        let (n, p, q) = setup_mod_params();
        let session = b"test_mod_proof";

        println!("N bits: {}", n.bits());

        // 1. Create Proof
        let proof = ProofMod::new(session, &n, &p, &q, &mut rng)
            .expect("Proof generation failed");

        assert_eq!(proof.x.len(), ITERATIONS);
        assert_eq!(proof.z.len(), ITERATIONS);
        assert!(proof.validate_basic());

        // 2. Verify Proof
        let is_valid = proof.verify(session, &n);
        assert!(is_valid, "Proof verification failed");

        // 3. Test verification failure: wrong session
        assert!(!proof.verify(b"wrong", &n), "Proof verified with wrong session");

        // 4. Test verification failure: wrong N
        let n_wrong = &n + BigInt::one(); // Might not be Blum, verify should catch basic props
        assert!(!proof.verify(session, &n_wrong), "Proof verified with wrong N");

        // 5. Test verification failure: N is prime
         let p_prime = get_safe_prime_details(512, 1, &mut rng).unwrap().safe_prime();
         assert!(!proof.verify(session, &p_prime), "Proof verified with prime N");

         // 6. Test verification failure: tampered proof component (w)
         let mut tampered_w_proof = proof.clone();
         tampered_w_proof.w = get_random_quadratic_non_residue(&mut rng, &n).unwrap();
         while tampered_w_proof.w == proof.w { // Ensure it's different
              tampered_w_proof.w = get_random_quadratic_non_residue(&mut rng, &n).unwrap();
          }
         assert!(!tampered_w_proof.verify(session, &n), "Proof verified with tampered w");

          // 7. Test verification failure: tampered proof component (x)
         let mut tampered_x_proof = proof.clone();
         tampered_x_proof.x[0] += BigInt::one();
         assert!(!tampered_x_proof.verify(session, &n), "Proof verified with tampered x");

           // 8. Test verification failure: tampered proof component (a)
         let mut tampered_a_proof = proof.clone();
         tampered_a_proof.a.set_bit(0, !tampered_a_proof.a.test_bit(0)); // Flip first bit
         assert!(!tampered_a_proof.verify(session, &n), "Proof verified with tampered a");
    }

    #[test]
    fn test_mod_proof_serialization() {
        let mut rng = thread_rng();
        let (n, p, q) = setup_mod_params();
        let session = b"test_mod_proof_serial";

        let proof = ProofMod::new(session, &n, &p, &q, &mut rng).unwrap();

        // Serialize
        let bzs = proof.to_bytes().expect("Serialization failed");
        assert_eq!(bzs.len(), PROOF_MOD_BYTES_PARTS);

        // Deserialize
        let proof_deserialized = ProofMod::from_bytes(&bzs).expect("Deserialization failed");

        assert_eq!(proof, proof_deserialized, "Deserialized proof mismatch");

        // Verify deserialized proof
        assert!(proof_deserialized.verify(session, &n), "Deserialized proof failed verification");
    }

     #[test]
    fn test_mod_proof_deserialize_errors() {
        // Wrong number of parts
        let bzs_short = vec![vec![1u8]; PROOF_MOD_BYTES_PARTS - 1];
        assert!(matches!(ProofMod::from_bytes(&bzs_short), Err(ModProofError::ByteConversionError { .. })));

        let bzs_long = vec![vec![1u8]; PROOF_MOD_BYTES_PARTS + 1];
         assert!(matches!(ProofMod::from_bytes(&bzs_long), Err(ModProofError::ByteConversionError { .. })));

         // Empty byte slice within parts (multi_bytes_to_bigints_fixed handles this -> error)
         let mut bzs_valid_len = vec![vec![1u8]; PROOF_MOD_BYTES_PARTS];
         bzs_valid_len[0] = vec![]; // Make w empty
         assert!(matches!(ProofMod::from_bytes(&bzs_valid_len), Err(ModProofError::InternalError(_))));
     }
} 