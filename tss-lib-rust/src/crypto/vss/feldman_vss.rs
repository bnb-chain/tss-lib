// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Feldman VSS, based on Paul Feldman, 1987., A practical scheme for non-interactive verifiable secret sharing.
// In Foundations of Computer Science, 1987., 28th Annual Symposium on. IEEE, 427–43

// Translation of tss-lib-go/crypto/vss/feldman_vss.go

use crate::{
    common::{
        int::ModInt,
        random::get_random_positive_int,
    },
    crypto::ecpoint::{ECPoint, PointError}, // Assuming generic ECPoint
    tss::Curve, // Assuming trait for curve operations & params
};

use elliptic_curve::CurveArithmetic;
use elliptic_curve::scalar::Scalar;
use num_bigint_dig::{{BigInt, Sign}};
use num_traits::{{Zero, One}};
use rand::{{CryptoRng, RngCore}};
use serde::{{Deserialize, Serialize}};
use std::collections::HashSet;
use thiserror::Error;
use log::warn;


#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum VssError {
    #[error("not enough shares to satisfy the threshold (required: {0}, have: {1})")]
    NumSharesBelowThreshold(usize, usize),
    #[error("invalid parameters: {0}")]
    InvalidParameters(String),
    #[error("duplicate party index found: {0}")]
    DuplicateIndex(String),
    #[error("party index is zero, which is not allowed")]
    IndexIsZero,
    #[error("share verification failed for party {id}")]
    ShareVerificationError { id: BigInt },
    #[error("reconstruction failed: {0}")]
    ReconstructionError(String),
    #[error("point operation failed: {0}")]
    PointError(String),
}

impl From<PointError> for VssError {
    fn from(err: PointError) -> Self {
        VssError::PointError(err.to_string())
    }
}

/// Represents a VSS Share σᵢ for a party Pᵢ.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    pub threshold: usize,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub id: BigInt, // Corresponds to x_i
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub share: BigInt, // Corresponds to σ_i = f(x_i)
}

/// Represents the public verification vector V = [v₀, v₁, ..., vₜ] where vᵢ = g^aᵢ.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationVector<C: Curve + CurveArithmetic> {
     // Need to handle ECPoint serialization carefully
     #[serde(bound(serialize = "ECPoint<C>: Serialize", deserialize = "ECPoint<C>: Deserialize<'de>"))]
    pub vector: Vec<ECPoint<C>>,
}

/// Convenience type for a slice of Shares.
pub type Shares<'a> = &'a [Share];

/// Checks share IDs (indexes) for duplicates or zero values modulo the curve order `q`.
/// Returns the original indexes if valid.
pub fn check_indexes<
    C: Curve + CurveArithmetic
>(q: &BigInt, indexes: &[BigInt]) -> Result<(), VssError> {
    if indexes.is_empty() {
         // Or should this be allowed?
         return Err(VssError::InvalidParameters("Indexes slice cannot be empty".to_string()));
     }
    let mut visited = HashSet::new();
    let mod_q = ModInt::new(q.clone());

    for v in indexes {
        // Reduce index modulo q. Does ID need to be < q?
        // Original Go code reduces, let's follow that for now.
        let v_mod = mod_q.add(v, &BigInt::zero()); // Ensure positive result < q

        if v_mod.is_zero() {
            return Err(VssError::IndexIsZero);
        }
        let v_mod_str = v_mod.to_string();
        if !visited.insert(v_mod_str) {
            return Err(VssError::DuplicateIndex(v_mod.to_string()));
        }
    }
    Ok(())
}

/// Creates a new Feldman Verifiable Secret Sharing scheme.
/// Generates shares of the `secret` for parties identified by `indexes`,
/// with a given `threshold`.
/// Returns the verification vector `V` and the list of shares `σᵢ`.
pub fn create<
    C: Curve + CurveArithmetic,
    R: CryptoRng + RngCore,
>(
    q: &BigInt, // Curve order
    threshold: usize,
    secret: &BigInt,
    indexes: &[BigInt],
    rng: &mut R,
) -> Result<(VerificationVector<C>, Vec<Share>), VssError>
where
     // Bounds needed for ECPoint operations
     ECPoint<C>: Clone + PartialEq + Serialize + for<'de> Deserialize<'de>,
     // Assuming ECPoint::scalar_base_mult exists and takes BigInt
     // Assuming ECPoint implements Add and ScalarMult traits or methods
{
    if threshold < 1 {
        return Err(VssError::InvalidParameters("Threshold cannot be less than 1".to_string()));
    }
    if indexes.len() < threshold + 1 {
        return Err(VssError::NumSharesBelowThreshold(threshold + 1, indexes.len()));
    }
    check_indexes::<C>(q, indexes)?;

    // 1. Sample polynomial f(z) = a₀ + a₁z + ... + aₜzᵗ where a₀ = secret
    let poly = sample_polynomial(q, threshold, secret, rng);

    // 2. Compute verification vector V = [g^a₀, g^a₁, ..., g^aₜ]
    let v_vec: Vec<ECPoint<C>> = poly.iter()
        .map(|a_i| ECPoint::<C>::scalar_base_mult(a_i))
        .collect();
    let verification_vector = VerificationVector { vector: v_vec };

    // 3. Compute shares σᵢ = f(idᵢ) for each party i
    let shares_vec: Vec<Share> = indexes.iter()
        .map(|id| {
            let share_val = evaluate_polynomial(q, threshold, &poly, id);
            Share {
                threshold,
                id: id.clone(), // Use original ID provided
                share: share_val,
            }
        })
        .collect();

    Ok((verification_vector, shares_vec))
}

impl Share {
    /// Verifies a share `σᵢ` against the public verification vector `V`.
    /// Checks if g^σᵢ = Π (vⱼ)^(idᵢ^j) for j = 0 to t.
    pub fn verify<
        C: Curve + CurveArithmetic
    >(
        &self,
        q: &BigInt, // Curve order
        verification_vector: &VerificationVector<C>,
    ) -> bool
    where
         // Bounds needed for ECPoint operations
         ECPoint<C>: Clone + PartialEq + Serialize + for<'de> Deserialize<'de>,
         // Assuming ECPoint implements Add and ScalarMult traits or methods
    {
        if self.threshold + 1 != verification_vector.vector.len() {
             warn!("Share verify failed: threshold mismatch (share={}, vv={})", self.threshold, verification_vector.vector.len()-1);
            return false;
        }

        let vs = &verification_vector.vector;
        let mod_q = ModInt::new(q.clone());

        // Calculate the right side of the equation: Π (vⱼ)^(idᵢ^j) mod N
        // rhs = v₀ * v₁^id * v₂^(id²) * ... * vₜ^(idᵗ)

        let mut rhs = vs[0].clone(); // Initialize with v₀ = g^a₀
        let mut id_power_j = BigInt::one();

        for j in 1..=self.threshold {
            // id_power_j = id^j mod q
            id_power_j = mod_q.mul(&id_power_j, &self.id);

            // point_j = v_j ^ (id^j)
            let point_j = vs[j].scalar_mul(&id_power_j);

            // rhs = rhs + point_j (point addition)
            match rhs.add(&point_j) {
                 Ok(sum) => rhs = sum,
                 Err(_) => {
                     warn!("Share verify failed: point addition error during RHS calculation");
                     return false; // Error during point addition
                 }
             }
        }

        // Calculate the left side: g^σᵢ
        let lhs = ECPoint::<C>::scalar_base_mult(&self.share);

        // Compare lhs == rhs
        lhs == rhs
    }
}

/// Reconstructs the secret from a sufficient number of shares using Lagrange interpolation.
pub fn reconstruct_secret<
    C: Curve + CurveArithmetic
>(
    q: &BigInt, // Curve order
    shares: Shares,
) -> Result<BigInt, VssError> {
    if shares.is_empty() {
        return Err(VssError::ReconstructionError("Cannot reconstruct secret from empty shares".to_string()));
    }

    let threshold = shares[0].threshold;
    if shares.len() <= threshold {
        return Err(VssError::NumSharesBelowThreshold(threshold + 1, shares.len()));
    }

    // Use only the first t+1 shares for reconstruction
    let effective_shares = &shares[0..=threshold];
    let mod_q = ModInt::new(q.clone());

    let mut secret = BigInt::zero();

    for i in 0..effective_shares.len() {
        let share_i = &effective_shares[i];
        let id_i = &share_i.id;

        // Calculate Lagrange basis polynomial lᵢ(0)
        let mut lagrange_basis = BigInt::one();
        for j in 0..effective_shares.len() {
            if i == j {
                continue;
            }
            let id_j = &effective_shares[j].id;

            // term = id_j / (id_j - id_i) mod q
            let denominator = mod_q.sub(id_j, id_i);
            if denominator.is_zero() {
                 // This should not happen if check_indexes passed and IDs are distinct mod q
                 return Err(VssError::ReconstructionError(format!(
                     "Lagrange denominator is zero for i={}, j={} (id_i={}, id_j={})",
                     i, j, id_i, id_j
                 )));
             }
            let denominator_inv = mod_q.mod_inverse(&denominator)
                .ok_or_else(|| VssError::ReconstructionError(format!(
                     "Modular inverse failed for denominator (id_j - id_i) = {} mod {} for i={}, j={}",
                     denominator, q, i, j
                 )))?;

            let term = mod_q.mul(id_j, &denominator_inv);
            lagrange_basis = mod_q.mul(&lagrange_basis, &term);
        }

        // Add term: shareᵢ * lᵢ(0) mod q
        let term_i = mod_q.mul(&share_i.share, &lagrange_basis);
        secret = mod_q.add(&secret, &term_i);
    }

    Ok(secret)
}

// --- Private Helper Functions ---

/// Samples a random polynomial f(z) = a₀ + a₁z + ... + aₜzᵗ of degree `threshold`,
/// where a₀ = `secret` and other coefficients a₁, ..., aₜ are random values in Zq.
fn sample_polynomial<
    R: CryptoRng + RngCore
>(
    q: &BigInt, // Curve order
    threshold: usize,
    secret: &BigInt,
    rng: &mut R,
) -> Vec<BigInt> {
    let mut poly = Vec::with_capacity(threshold + 1);
    // a₀ = secret (reduced mod q? VSS normally operates in the field Zq)
    let mod_q = ModInt::new(q.clone());
    poly.push(mod_q.add(secret, &BigInt::zero())); // Ensure a0 is in Zq

    // a₁, ..., aₜ = random in Zq
    for _ in 1..=threshold {
        // Ensure coefficient is less than q
        let ai = get_random_positive_int(rng, q).unwrap_or_else(BigInt::zero);
        poly.push(ai);
    }
    poly
}

/// Evaluates the polynomial `poly` at point `id` modulo `q`.
/// poly = [a₀, a₁, ..., aₜ]
/// result = a₀ + a₁*id + a₂*id² + ... + aₜ*idᵗ mod q
fn evaluate_polynomial(
    q: &BigInt, // Curve order
    _threshold: usize, // Not strictly needed if poly length implies it
    poly: &[BigInt],
    id: &BigInt,
) -> BigInt {
    let mod_q = ModInt::new(q.clone());
    let mut result = poly.get(0).cloned().unwrap_or_else(BigInt::zero);
    let mut id_power_i = BigInt::one();

    for i in 1..poly.len() {
        // id_power_i = id^i mod q
        id_power_i = mod_q.mul(&id_power_i, id);

        // term = aᵢ * id^i mod q
        let term = mod_q.mul(&poly[i], &id_power_i);

        // result = (result + term) mod q
        result = mod_q.add(&result, &term);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tss::Secp256k1Curve; // Example curve
    use elliptic_curve::Field;
    use rand::thread_rng;

     // Helper to get curve order Q for K256
     fn get_k256_q() -> BigInt {
         let q_bytes = k256::Scalar::ORDER.to_be_bytes();
         BigInt::from_bytes_be(Sign::Plus, &q_bytes)
     }

    #[test]
    fn test_feldman_vss_create_verify_reconstruct() {
        let mut rng = thread_rng();
        let q = get_k256_q();

        let secret = BigInt::from(123456789012345_u64);
        let threshold = 2;
        let num_parties = 5;

        // Generate party IDs (must be > 0 and distinct mod q)
        let indexes: Vec<BigInt> = (1..=num_parties).map(BigInt::from).collect();

        // 1. Create VSS shares
        let create_result = create::<Secp256k1, _>(&q, threshold, &secret, &indexes, &mut rng);
        assert!(create_result.is_ok());
        let (verification_vector, shares_vec) = create_result.unwrap();

        assert_eq!(verification_vector.vector.len(), threshold + 1);
        assert_eq!(shares_vec.len(), num_parties as usize);

        println!("Secret: {}", secret);
        println!("Threshold: {}", threshold);
        println!("Verification Vector V[0]: {:?}", verification_vector.vector[0]); // g^a0 = g^secret
        // println!("Shares: {:?}", shares_vec);

        // 2. Verify each share
        for share in &shares_vec {
            println!("Verifying share for ID: {}", share.id);
            assert!(share.verify::<Secp256k1>(&q, &verification_vector), "Share verification failed for ID {}", share.id);
        }

        // 3. Reconstruct secret with enough shares (t+1)
        let shares_to_reconstruct = &shares_vec[0..=threshold];
        let reconstructed_secret = reconstruct_secret::<Secp256k1>(&q, shares_to_reconstruct)
            .expect("Secret reconstruction failed");

        println!("Reconstructed Secret: {}", reconstructed_secret);
        assert_eq!(secret, reconstructed_secret);

         // 4. Reconstruct with different set of t+1 shares
         let shares_to_reconstruct_alt = &shares_vec[num_parties as usize - threshold - 1..];
         assert_eq!(shares_to_reconstruct_alt.len(), threshold + 1);
         let reconstructed_secret_alt = reconstruct_secret::<Secp256k1>(&q, shares_to_reconstruct_alt)
             .expect("Secret reconstruction (alt set) failed");
         assert_eq!(secret, reconstructed_secret_alt);

        // 5. Attempt reconstruction with insufficient shares (t)
        let shares_insufficient = &shares_vec[0..threshold];
        let recon_insufficient = reconstruct_secret::<Secp256k1>(&q, shares_insufficient);
        assert!(matches!(recon_insufficient, Err(VssError::NumSharesBelowThreshold(_, _))));
    }

    #[test]
    fn test_verify_fail_tampered_share() {
        let mut rng = thread_rng();
        let q = get_k256_q();
        let secret = BigInt::from(999u64);
        let threshold = 1;
        let indexes = vec![BigInt::from(1), BigInt::from(2)];

        let (vv, mut shares_vec) = create::<Secp256k1, _>(&q, threshold, &secret, &indexes, &mut rng).unwrap();

        // Tamper with a share value
        shares_vec[0].share += BigInt::one();

        assert!(!shares_vec[0].verify::<Secp256k1>(&q, &vv), "Tampered share verified successfully");
        assert!(shares_vec[1].verify::<Secp256k1>(&q, &vv), "Untampered share failed verification");
    }

    #[test]
    fn test_verify_fail_wrong_vv() {
         let mut rng = thread_rng();
        let q = get_k256_q();
        let secret = BigInt::from(888u64);
        let threshold = 1;
        let indexes = vec![BigInt::from(1), BigInt::from(2)];

        let (vv1, shares1) = create::<Secp256k1, _>(&q, threshold, &secret, &indexes, &mut rng).unwrap();
        // Create shares/VV for a *different* secret
        let secret2 = BigInt::from(777u64);
        let (vv2, _) = create::<Secp256k1, _>(&q, threshold, &secret2, &indexes, &mut rng).unwrap();

        // Try to verify shares from secret1 against vv from secret2
        assert!(!shares1[0].verify::<Secp256k1>(&q, &vv2), "Share verified against wrong VV");
        assert!(shares1[0].verify::<Secp256k1>(&q, &vv1), "Share failed against correct VV");
    }

     #[test]
    fn test_check_indexes() {
        let q = get_k256_q();
        assert!(check_indexes::<Secp256k1>(&q, &[BigInt::one(), BigInt::two()]).is_ok());
        // Zero index
        assert!(matches!(check_indexes::<Secp256k1>(&q, &[BigInt::one(), BigInt::zero()]), Err(VssError::IndexIsZero)));
        // Duplicate index
        assert!(matches!(check_indexes::<Secp256k1>(&q, &[BigInt::one(), BigInt::two(), BigInt::one()]), Err(VssError::DuplicateIndex(_))));
         // Duplicate index (after mod q)
         let q_plus_1 = &q + BigInt::one();
         assert!(matches!(check_indexes::<Secp256k1>(&q, &[BigInt::one(), q_plus_1]), Err(VssError::DuplicateIndex(_))));
         // Empty
         assert!(matches!(check_indexes::<Secp256k1>(&q, &[]), Err(VssError::InvalidParameters(_))));

    }

    #[test]
    fn test_create_errors() {
        let mut rng = thread_rng();
        let q = get_k256_q();
        let secret = BigInt::from(1u64);
        let indexes = vec![BigInt::one(), BigInt::two()];

        // Threshold too low
        assert!(matches!(create::<Secp256k1, _>(&q, 0, &secret, &indexes, &mut rng), Err(VssError::InvalidParameters(_))));

        // Not enough indexes for threshold
        assert!(matches!(create::<Secp256k1, _>(&q, 2, &secret, &indexes, &mut rng), Err(VssError::NumSharesBelowThreshold(_, _))));

        // Invalid indexes
        let invalid_indexes = vec![BigInt::one(), BigInt::zero()];
        assert!(matches!(create::<Secp256k1, _>(&q, 1, &secret, &invalid_indexes, &mut rng), Err(VssError::IndexIsZero)));
    }
} 