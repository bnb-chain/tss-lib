// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/crypto/mta/range_proof.go

use crate::{
    common::{
        hash::sha512_256i,
        hash_utils::rejection_sample,
        int::ModInt,
        random::{get_random_positive_int, get_random_positive_relatively_prime_int},
        slice::{multi_bytes_to_bigints, bigints_to_bytes, non_empty_multi_bytes},
        int::is_in_interval,
    },
    crypto::paillier::PublicKey,
    tss::Curve, // Assuming trait for curve operations & params
};

use elliptic_curve::CurveArithmetic;
use num_bigint_dig::{{BigInt, Sign}};
use num_integer::Integer;
use num_traits::{{Zero, One}};
use rand::{{CryptoRng, RngCore}};
use serde::{{Deserialize, Serialize}};
use thiserror::Error;
use log::error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RangeProofError {
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

const RANGE_PROOF_ALICE_BYTES_PARTS: usize = 6;

/// Alice's range proof for MtA protocols. (GG18Spec Fig. 9)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeProofAlice {
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub z: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub u: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub w: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub s: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub s1: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub s2: BigInt,
}

impl RangeProofAlice {
    /// Generates Alice's range proof. (GG18Spec Fig. 9)
    #[allow(clippy::too_many_arguments)]
    pub fn new<C, R>(
        curve_q: &BigInt, // EC curve order
        pk: &PublicKey,   // Paillier public key
        c: &BigInt,       // Ciphertext c = Enc(m, r)
        n_tilde: &BigInt, // N~
        h1: &BigInt,
        h2: &BigInt,
        m: &BigInt,       // Original message m
        r: &BigInt,       // Paillier encryption randomness for c
        rng: &mut R,
    ) -> Result<Self, RangeProofError>
    where
        C: Curve + CurveArithmetic,
        R: CryptoRng + RngCore,
    {
         // Simplified parameter checks
         if pk.n.sign() != Sign::Plus || n_tilde.sign() != Sign::Plus || h1.sign() != Sign::Plus || h2.sign() != Sign::Plus {
             return Err(RangeProofError::InvalidParameters("Negative N, Ntilde, h1, or h2".to_string()));
         }
         // Check m range? Range proof implicitly proves m is in range [-q^3, q^3] roughly
         // if m.sign() == Sign::Minus || m >= curve_q {
         //     return Err(RangeProofError::InvalidParameters("Message m out of range [0, q)".to_string()));
         // }

        let n = &pk.n;
        let n_square = pk.n_square();
        let mod_n_tilde = ModInt::new(n_tilde.clone());
        let mod_n_square = ModInt::new(n_square.clone());
        let mod_n = ModInt::new(n.clone());
        let mod_q = ModInt::new(curve_q.clone());

        // Precompute powers of q
        let q2 = mod_q.mul(curve_q, curve_q);
        let q3 = mod_q.mul(curve_q, &q2);

        // Precompute products involving q
        let q_n_tilde = curve_q * n_tilde;
        let q3_n_tilde = &q3 * n_tilde;

        // 1. alpha <- Z_(q^3)
        let alpha = get_random_positive_int(rng, &q3)
            .ok_or_else(|| RangeProofError::ProofGenerationError("Failed to generate alpha".to_string()))?;

        // 2. beta <- Z*_N
        let beta = get_random_positive_relatively_prime_int(rng, n)
            .ok_or_else(|| RangeProofError::ProofGenerationError("Failed to generate beta".to_string()))?;

        // 3. gamma <- Z_(q^3 * N_tilde)
        let gamma = get_random_positive_int(rng, &q3_n_tilde)
            .ok_or_else(|| RangeProofError::ProofGenerationError("Failed to generate gamma".to_string()))?;

        // 4. rho <- Z_(q * N_tilde)
        let rho = get_random_positive_int(rng, &q_n_tilde)
            .ok_or_else(|| RangeProofError::ProofGenerationError("Failed to generate rho".to_string()))?;

        // 5. z = h1^m * h2^rho mod N_tilde
        let h1_m = mod_n_tilde.exp(h1, m);
        let h2_rho = mod_n_tilde.exp(h2, &rho);
        let z = mod_n_tilde.mul(&h1_m, &h2_rho);

        // 6. u = Gamma^alpha * beta^N mod N^2
        let gamma_alpha = mod_n_square.exp(&pk.gamma(), &alpha);
        let beta_n = mod_n_square.exp(&beta, n);
        let u = mod_n_square.mul(&gamma_alpha, &beta_n);

        // 7. w = h1^alpha * h2^gamma mod N_tilde
        let h1_alpha = mod_n_tilde.exp(h1, &alpha);
        let h2_gamma = mod_n_tilde.exp(h2, &gamma);
        let w = mod_n_tilde.mul(&h1_alpha, &h2_gamma);

        // 8-9. Compute challenge e = H(pk, c, z, u, w)
        let e: BigInt;
        {
            let pk_ints = pk.as_ints(); // [N, Gamma]
            let hash_input = vec![&pk_ints[0], &pk_ints[1], c, &z, &u, &w];
            let e_hash = sha512_256i(&hash_input)
                .ok_or_else(|| RangeProofError::ProofGenerationError("Failed to compute challenge hash e".to_string()))?;
            e = rejection_sample(curve_q, &e_hash);
        }

        // 10. s = r^e * beta mod N
        let r_e = mod_n.exp(r, &e);
        let s = mod_n.mul(&r_e, &beta);

        // 11. s1 = alpha + e*m
        // Go code adds without mod. Stick to that.
        let em = &e * m;
        let s1 = &alpha + &em;

        // 12. s2 = gamma + e*rho
        // Go code adds without mod. Stick to that.
        let e_rho = &e * &rho;
        let s2 = &gamma + &e_rho;

        Ok(Self { z, u, w, s, s1, s2 })
    }

    /// Verifies Alice's range proof. (GG18Spec Fig. 9)
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        curve_q: &BigInt,
        pk: &PublicKey,
        n_tilde: &BigInt,
        h1: &BigInt,
        h2: &BigInt,
        c: &BigInt, // Ciphertext c = Enc(m, r)
    ) -> bool {
         if !self.validate_basic() || pk.n.sign() != Sign::Plus || n_tilde.sign() != Sign::Plus {
            error!("RangeProofAlice verify: failed basic validation or invalid pk/Ntilde");
            return false;
        }

        let n = &pk.n;
        let n_square = pk.n_square();
        let mod_n_tilde = ModInt::new(n_tilde.clone());
        let mod_n_square = ModInt::new(n_square.clone());

        // Check ranges and GCDs
        let q3 = curve_q.pow(3);
        if !is_in_interval(&self.z, n_tilde) || !is_in_interval(&self.u, &n_square) ||
           !is_in_interval(&self.w, n_tilde) || !is_in_interval(&self.s, n)
         {
             error!("RangeProofAlice verify: interval check failed");
             return false;
         }
        // Check s1, s2 are in [-q^3, q^3]? Fig 9 says s1 in Z. Check if s1 is in range.
        // The check `pf.S1.Cmp(q3) == 1` in Go implies s1 > q3 is invalid.
        // It does not check for negative s1.
         if self.s1.abs() > q3 { // Check absolute value against q^3 bound
              error!("RangeProofAlice verify: s1 out of range [-q^3, q^3]");
             return false;
         }
         // No explicit range check for s2 in Go code's verify, only for s1 vs q3.

        if self.z.gcd(n_tilde) != BigInt::one() || self.u.gcd(&n_square) != BigInt::one() ||
           self.w.gcd(n_tilde) != BigInt::one() || self.s.gcd(n) != BigInt::one()
        {
             error!("RangeProofAlice verify: GCD check failed");
            return false;
        }

        // Recalculate challenge e = H(...)
        let e: BigInt;
        {
            let pk_ints = pk.as_ints();
            let hash_input = vec![&pk_ints[0], &pk_ints[1], c, &self.z, &self.u, &self.w];
             let e_hash = match sha512_256i(&hash_input) {
                 Some(h) => h,
                 None => { error!("RangeProofAlice verify: Failed to compute challenge hash e"); return false; }
             };
             e = rejection_sample(curve_q, &e_hash);
         }

        // Verification Check 1: u == Gamma^s1 * s^N * c^-e mod N^2
        let gamma_s1 = mod_n_square.exp(&pk.gamma(), &self.s1);
        let s_n = mod_n_square.exp(&self.s, n);
        // Calculate c^-e = (c^-1)^e mod N^2
        let minus_e = curve_q - &e; // Assuming e is positive from rejection sample
        let c_inv = mod_n_square.mod_inverse(c);
         let c_pow_minus_e = match c_inv {
             Some(inv) => mod_n_square.exp(&inv, &e),
             None => { error!("RangeProofAlice verify: Inverse of c mod N^2 failed"); return false; } // If c not invertible? Should be.
         };
        // // Alternative: Calculate c^(-e mod lambda(N^2)) ? Simpler to do inverse then power.
        // let c_pow_minus_e = mod_n_square.exp(c, &minus_e);

        let rhs1_tmp = mod_n_square.mul(&gamma_s1, &s_n);
        let rhs1 = mod_n_square.mul(&rhs1_tmp, &c_pow_minus_e);

        if self.u != rhs1 {
            error!("RangeProofAlice verify: Check 1 failed (u)");
            return false;
        }

        // Verification Check 2: w == h1^s1 * h2^s2 * z^-e mod N_tilde
        let h1_s1 = mod_n_tilde.exp(h1, &self.s1);
        let h2_s2 = mod_n_tilde.exp(h2, &self.s2);
        // Calculate z^-e = (z^-1)^e mod N_tilde
        let z_inv = mod_n_tilde.mod_inverse(&self.z);
        let z_pow_minus_e = match z_inv {
             Some(inv) => mod_n_tilde.exp(&inv, &e),
             None => { error!("RangeProofAlice verify: Inverse of z mod N_tilde failed"); return false; }
         };
        // // Alternative: Calculate z^(-e mod phi(N_tilde)) ?
        // let z_pow_minus_e = mod_n_tilde.exp(&self.z, &minus_e);

        let rhs2_tmp = mod_n_tilde.mul(&h1_s1, &h2_s2);
        let rhs2 = mod_n_tilde.mul(&rhs2_tmp, &z_pow_minus_e);

        if self.w != rhs2 {
             error!("RangeProofAlice verify: Check 2 failed (w)");
            return false;
        }

        true
    }

    /// Basic validation ensuring all components are non-zero.
    pub fn validate_basic(&self) -> bool {
         !self.z.is_zero() && !self.u.is_zero() && !self.w.is_zero() &&
         !self.s.is_zero() && !self.s1.is_zero() && !self.s2.is_zero()
         // Should also check signs? Proof generation should yield positive z, u, w, s.
         // s1, s2 can be negative but are checked against q^3 in verify.
    }

    /// Converts the proof to a vector of byte vectors.
    pub fn to_bytes(&self) -> Result<Vec<Vec<u8>>, RangeProofError> {
         let parts = vec![
             &self.z, &self.u, &self.w, &self.s, &self.s1, &self.s2
         ];
         Ok(bigints_to_bytes(&parts))
     }

    /// Creates a RangeProofAlice from a slice of byte vectors.
    pub fn from_bytes(bzs: &[Vec<u8>]) -> Result<Self, RangeProofError> {
        if bzs.len() != RANGE_PROOF_ALICE_BYTES_PARTS {
            return Err(RangeProofError::ByteConversionError{ expected: RANGE_PROOF_ALICE_BYTES_PARTS, got: bzs.len() });
        }
         let ints = multi_bytes_to_bigints(bzs);
         if ints.len() != RANGE_PROOF_ALICE_BYTES_PARTS {
              return Err(RangeProofError::InternalError("BigInt conversion length mismatch".to_string()));
         }
         Ok(Self {
             z: ints[0].clone(),
             u: ints[1].clone(),
             w: ints[2].clone(),
             s: ints[3].clone(),
             s1: ints[4].clone(),
             s2: ints[5].clone(),
         })
     }
}

#[cfg(test)]
mod tests {
     use super::*;
    use crate::{crypto::paillier, tss::Secp256k1Curve};
    use k256::Secp256k1;
    use rand::thread_rng;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tokio::runtime::Runtime;

     // Helper to get curve order Q for K256
     fn get_k256_q() -> BigInt {
         let q_bytes = k256::Scalar::ORDER.to_be_bytes();
         BigInt::from_bytes_be(num_bigint_dig::Sign::Plus, &q_bytes)
     }

    // Generate common parameters for testing
    async fn setup_range_proof_params(rng_arc: Arc<Mutex<thread_rng::ThreadRng>>) -> (PublicKey, BigInt, BigInt, BigInt) {
        let bits = 1024; // Smaller for testing
        let (_paillier_sk, paillier_pk) = paillier::generate_key_pair(Arc::clone(&rng_arc), bits, 1).await.unwrap();
        let q = get_k256_q();
        // Need N_tilde, h1, h2 appropriate for the Paillier key N
        // Generating random ones for now, but ideally derived correctly.
         let n_tilde = get_random_positive_int(&mut *rng_arc.lock().await, &paillier_pk.n).unwrap();
        let h1 = get_random_positive_relatively_prime_int(&mut *rng_arc.lock().await, &n_tilde).unwrap();
        let h2 = get_random_positive_relatively_prime_int(&mut *rng_arc.lock().await, &n_tilde).unwrap();
        (paillier_pk, n_tilde, h1, h2)
    }

    #[tokio::test]
    async fn test_mta_range_proof_alice() {
        let mut rng_thread = thread_rng();
        let rng_arc = Arc::new(Mutex::new(rng_thread));
        let (pk, n_tilde, h1, h2) = setup_range_proof_params(Arc::clone(&rng_arc)).await;
        let q = get_k256_q();

        // Message m should be in range [-q^3, q^3] for the proof
        // Typically m is much smaller, e.g., a secret key share.
        let m = get_random_positive_int(&mut *rng_arc.lock().await, &q).unwrap(); // m < q

        // Encrypt m to get c and r
        let (c, r) = pk.encrypt_and_return_randomness(&mut *rng_arc.lock().await, &m).unwrap();

        // Create proof
        let proof = RangeProofAlice::new::<Secp256k1, _>(
            &q, &pk, &c, &n_tilde, &h1, &h2, &m, &r, &mut *rng_arc.lock().await
        ).unwrap();

        // Verify proof
        let is_valid = proof.verify(&q, &pk, &n_tilde, &h1, &h2, &c);
        assert!(is_valid, "RangeProofAlice verification failed");

        // Test serialization/deserialization
        let bytes = proof.to_bytes().unwrap();
        assert_eq!(bytes.len(), RANGE_PROOF_ALICE_BYTES_PARTS);
        let proof_recon = RangeProofAlice::from_bytes(&bytes).unwrap();
        assert_eq!(proof, proof_recon);

         // Test failure: Tampered proof component (e.g., z)
         let mut tampered_proof = proof.clone();
         tampered_proof.z += BigInt::one();
         assert!(!tampered_proof.verify(&q, &pk, &n_tilde, &h1, &h2, &c), "Tampered proof verification succeeded");

         // Test failure: Wrong ciphertext c
         let m_wrong = &m + BigInt::one();
         let (c_wrong, _) = pk.encrypt_and_return_randomness(&mut *rng_arc.lock().await, &m_wrong).unwrap();
         assert!(!proof.verify(&q, &pk, &n_tilde, &h1, &h2, &c_wrong), "Proof verified with wrong ciphertext");
    }

     #[tokio::test]
     async fn test_range_proof_boundaries() {
         // Test with m = 0
         let mut rng_thread = thread_rng();
        let rng_arc = Arc::new(Mutex::new(rng_thread));
        let (pk, n_tilde, h1, h2) = setup_range_proof_params(Arc::clone(&rng_arc)).await;
        let q = get_k256_q();
         let m0 = BigInt::zero();
         let (c0, r0) = pk.encrypt_and_return_randomness(&mut *rng_arc.lock().await, &m0).unwrap();
         let proof0 = RangeProofAlice::new::<Secp256k1, _>(&q, &pk, &c0, &n_tilde, &h1, &h2, &m0, &r0, &mut *rng_arc.lock().await).unwrap();
         assert!(proof0.verify(&q, &pk, &n_tilde, &h1, &h2, &c0), "Proof failed for m=0");

         // Test with large m (but still within implicit bound q^3)
         // Note: m should represent a value within the group usually, so m < q is typical.
         // Testing with m near q^3 might require adjustments if intermediate values overflow BigInt.
         // let m_large = &q * &q; // Example large m
         // let (c_large, r_large) = pk.encrypt_and_return_randomness(&mut *rng_arc.lock().await, &m_large).unwrap();
         // let proof_large = RangeProofAlice::new::<Secp256k1, _>(&q, &pk, &c_large, &n_tilde, &h1, &h2, &m_large, &r_large, &mut *rng_arc.lock().await).unwrap();
         // assert!(proof_large.verify(&q, &pk, &n_tilde, &h1, &h2, &c_large), "Proof failed for large m");

          // Test with negative m (proof generation might handle it, but verify likely fails range checks implicitly)
         // let m_neg = BigInt::from(-100i64);
         // let (c_neg, r_neg) = pk.encrypt_and_return_randomness(&mut *rng_arc.lock().await, &m_neg).unwrap_or_else(|_| panic!("Encryption should allow negative for test")); // Allow encryption outside Paillier spec for test?
         // let proof_neg = RangeProofAlice::new::<Secp256k1, _>(&q, &pk, &c_neg, &n_tilde, &h1, &h2, &m_neg, &r_neg, &mut *rng_arc.lock().await).unwrap();
         // assert!(!proof_neg.verify(&q, &pk, &n_tilde, &h1, &h2, &c_neg), "Proof verified for negative m");

     }

} 