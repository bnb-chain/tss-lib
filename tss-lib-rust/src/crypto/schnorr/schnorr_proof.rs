// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/crypto/schnorr/schnorr_proof.go

use crate::{
    common::{
        hash::sha512_256i_tagged,
        int::ModInt,
        random::get_random_positive_int,
        hash_utils::rejection_sample,
    },
    crypto::ecpoint::{ECPoint, PointError},
    tss::Curve, // Assuming trait for curve operations & params
};

use elliptic_curve::CurveArithmetic;
use elliptic_curve::scalar::Scalar;
use num_bigint_dig::{BigInt};
use num_traits::Zero;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use log::error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SchnorrError {
    #[error("invalid parameters: {0}")]
    InvalidParameters(String),
    #[error("point operation failed: {0}")]
    PointError(String),
    #[error("internal error: {0}")]
    InternalError(String),
}

impl From<PointError> for SchnorrError {
    fn from(err: PointError) -> Self {
        SchnorrError::PointError(err.to_string())
    }
}

/// Schnorr ZK proof of knowledge of the discrete logarithm `x` such that `X = g^x`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProof<C: Curve + CurveArithmetic> {
     // Need to handle ECPoint serialization
    #[serde(bound(serialize = "ECPoint<C>: Serialize", deserialize = "ECPoint<C>: Deserialize<'de>"))]
    pub alpha: ECPoint<C>,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub t: BigInt,
}

/// Schnorr ZK proof of knowledge `s`, `l` such that `V = R^s * g^l`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkvProof<C: Curve + CurveArithmetic> {
    // Need to handle ECPoint serialization
    #[serde(bound(serialize = "ECPoint<C>: Serialize", deserialize = "ECPoint<C>: Deserialize<'de>"))]
    pub alpha: ECPoint<C>,
     #[serde(with = "crate::serde_support::bigint_bytes")]
    pub t: BigInt,
     #[serde(with = "crate::serde_support::bigint_bytes")]
    pub u: BigInt,
}

impl<C> ZkProof<C>
where
    C: Curve + CurveArithmetic,
    // Add bounds needed for ECPoint ops
     ECPoint<C>: Clone + PartialEq + Serialize + for<'de> Deserialize<'de>,
    // Assuming methods exist & BigInt can be converted to Scalar
{
    /// Creates a new Schnorr ZK proof `(α, t)` for `X = g^x`. (GG18Spec Fig. 16)
    /// `α = g^a`
    /// `c = H(session, X, g, α)`
    /// `t = a + c*x mod q`
    pub fn new<
        R: CryptoRng + RngCore
    >(
        session: &[u8],
        x_priv: &BigInt,       // The secret x
        x_pub: &ECPoint<C>, // The public point X = g^x
        rng: &mut R,
    ) -> Result<Self, SchnorrError> {
         if x_priv.sign() == num_bigint_dig::Sign::Minus || !x_pub.validate_basic() {
             return Err(SchnorrError::InvalidParameters("x or X are invalid".to_string()));
         }
        let q = C::ORDER_BIGINT; // Assuming Curve trait provides this
        let mod_q = ModInt::new(q.clone());
        let g = ECPoint::<C>::generator(); // Assuming generator access

        // a <- Zq
        let a = get_random_positive_int(rng, &q)
            .ok_or_else(|| SchnorrError::InternalError("Failed to generate random 'a'".to_string()))?;

        // α = g^a
        let alpha = ECPoint::<C>::scalar_base_mult(&a);

        // c = H(session, X, g, α)
        let (x_pub_x, x_pub_y) = x_pub.coords();
        let (g_x, g_y) = g.coords();
        let (alpha_x, alpha_y) = alpha.coords();

        let c_hash = sha512_256i_tagged(
            session,
            &[&x_pub_x, &x_pub_y, &g_x, &g_y, &alpha_x, &alpha_y],
        ).ok_or_else(|| SchnorrError::InternalError("Failed to compute challenge hash c".to_string()))?;

        // Rejection sample c
        let c = rejection_sample(&q, &c_hash);

        // t = a + c*x mod q
        let cx = mod_q.mul(&c, x_priv);
        let t = mod_q.add(&a, &cx);

        Ok(Self { alpha, t })
    }

    /// Verifies a Schnorr ZK proof. (GG18Spec Fig. 16)
    /// Checks if `g^t == α * X^c`
    pub fn verify(
        &self,
        session: &[u8],
        x_pub: &ECPoint<C>, // The public point X = g^x
    ) -> bool {
         if !self.validate_basic() || !x_pub.validate_basic() {
             return false;
         }
        let q = C::ORDER_BIGINT;
        let mod_q = ModInt::new(q.clone());
        let g = ECPoint::<C>::generator();

        // Recalculate c = H(session, X, g, α)
        let (x_pub_x, x_pub_y) = x_pub.coords();
        let (g_x, g_y) = g.coords();
        let (alpha_x, alpha_y) = self.alpha.coords();

         let c_hash = match sha512_256i_tagged(
             session,
             &[&x_pub_x, &x_pub_y, &g_x, &g_y, &alpha_x, &alpha_y],
         ) {
             Some(h) => h,
             None => {
                 error!("ZKProof verify: failed to compute challenge hash c");
                 return false;
             }
         };

        let c = rejection_sample(&q, &c_hash);

        // Left side: g^t
        let gt = ECPoint::<C>::scalar_base_mult(&self.t);

        // Right side: α * X^c
        let xc = x_pub.scalar_mul(&c);
        let alpha_plus_xc = match self.alpha.add(&xc) {
            Ok(p) => p,
            Err(_) => {
                 error!("ZKProof verify: point addition failed for alpha * X^c");
                 return false;
            }
         };

        // Check g^t == α * X^c
        gt == alpha_plus_xc
    }

    /// Basic validation of proof components.
    pub fn validate_basic(&self) -> bool {
        self.alpha.validate_basic() // t is BigInt, always valid
    }
}

impl<C> ZkvProof<C>
where
    C: Curve + CurveArithmetic,
    // Add bounds needed for ECPoint ops
     ECPoint<C>: Clone + PartialEq + Serialize + for<'de> Deserialize<'de>,
{
    /// Creates a new Schnorr ZK proof `(α, t, u)` for `V = R^s * g^l`. (GG18Spec Fig. 17)
    /// `α = R^a * g^b`
    /// `c = H(session, V, R, g, α)`
    /// `t = a + c*s mod q`
    /// `u = b + c*l mod q`
    pub fn new<
        R: CryptoRng + RngCore
    >(
        session: &[u8],
        s: &BigInt, // Secret s
        l: &BigInt, // Secret l
        v_pub: &ECPoint<C>, // Public V = R^s * g^l
        r_pub: &ECPoint<C>, // Public R
        rng: &mut R,
    ) -> Result<Self, SchnorrError> {
         if s.sign() == num_bigint_dig::Sign::Minus ||
            l.sign() == num_bigint_dig::Sign::Minus ||
            !v_pub.validate_basic() ||
            !r_pub.validate_basic()
         {
             return Err(SchnorrError::InvalidParameters("s, l, V, or R are invalid".to_string()));
         }
        let q = C::ORDER_BIGINT;
        let mod_q = ModInt::new(q.clone());
        let g = ECPoint::<C>::generator();

        // a, b <- Zq
        let a = get_random_positive_int(rng, &q)
            .ok_or_else(|| SchnorrError::InternalError("Failed to generate random 'a'".to_string()))?;
        let b = get_random_positive_int(rng, &q)
            .ok_or_else(|| SchnorrError::InternalError("Failed to generate random 'b'".to_string()))?;

        // α = R^a * g^b
        let ra = r_pub.scalar_mul(&a);
        let gb = ECPoint::<C>::scalar_base_mult(&b);
        let alpha = ra.add(&gb)?; // Handle potential point error

        // c = H(session, V, R, g, α)
        let (v_x, v_y) = v_pub.coords();
        let (r_x, r_y) = r_pub.coords();
        let (g_x, g_y) = g.coords();
        let (alpha_x, alpha_y) = alpha.coords();

        let c_hash = sha512_256i_tagged(
            session,
            &[&v_x, &v_y, &r_x, &r_y, &g_x, &g_y, &alpha_x, &alpha_y],
        ).ok_or_else(|| SchnorrError::InternalError("Failed to compute challenge hash c".to_string()))?;
        let c = rejection_sample(&q, &c_hash);

        // t = a + c*s mod q
        let cs = mod_q.mul(&c, s);
        let t = mod_q.add(&a, &cs);

        // u = b + c*l mod q
        let cl = mod_q.mul(&c, l);
        let u = mod_q.add(&b, &cl);

        Ok(Self { alpha, t, u })
    }

    /// Verifies a Schnorr ZK proof `(α, t, u)`. (GG18Spec Fig. 17)
    /// Checks if `R^t * g^u == α * V^c`
    pub fn verify(
        &self,
        session: &[u8],
        v_pub: &ECPoint<C>,
        r_pub: &ECPoint<C>,
    ) -> bool {
         if !self.validate_basic() || !v_pub.validate_basic() || !r_pub.validate_basic() {
            return false;
        }
        let q = C::ORDER_BIGINT;
        let mod_q = ModInt::new(q.clone());
        let g = ECPoint::<C>::generator();

        // Recalculate c = H(session, V, R, g, α)
        let (v_x, v_y) = v_pub.coords();
        let (r_x, r_y) = r_pub.coords();
        let (g_x, g_y) = g.coords();
        let (alpha_x, alpha_y) = self.alpha.coords();

        let c_hash = match sha512_256i_tagged(
            session,
            &[&v_x, &v_y, &r_x, &r_y, &g_x, &g_y, &alpha_x, &alpha_y],
         ) {
            Some(h) => h,
            None => {
                error!("ZKVProof verify: failed to compute challenge hash c");
                return false;
            }
        };
        let c = rejection_sample(&q, &c_hash);

        // Left side: R^t * g^u
        let rt = r_pub.scalar_mul(&self.t);
        let gu = ECPoint::<C>::scalar_base_mult(&self.u);
        let lhs = match rt.add(&gu) {
            Ok(p) => p,
            Err(_) => {
                 error!("ZKVProof verify: point addition failed for R^t * g^u");
                 return false;
            }
         };

        // Right side: α * V^c
        let vc = v_pub.scalar_mul(&c);
        let rhs = match self.alpha.add(&vc) {
            Ok(p) => p,
             Err(_) => {
                 error!("ZKVProof verify: point addition failed for alpha * V^c");
                 return false;
            }
         };

        // Check R^t * g^u == α * V^c
        lhs == rhs
    }

    /// Basic validation of proof components.
    pub fn validate_basic(&self) -> bool {
        self.alpha.validate_basic() // t, u are BigInts, always valid
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::ecpoint::ECPoint, tss::Secp256k1Curve};
    use k256::Secp256k1;
    use rand::thread_rng;
    use elliptic_curve::group::Group;

     // Helper to get curve order Q for K256
     fn get_k256_q() -> BigInt {
         let q_bytes = k256::Scalar::ORDER.to_be_bytes();
         BigInt::from_bytes_be(num_bigint_dig::Sign::Plus, &q_bytes)
     }

    #[test]
    fn test_zkp_proof_verify() {
        let mut rng = thread_rng();
        let q = get_k256_q();

        // Setup: secret x, public X = g^x
        let x_priv = get_random_positive_int(&mut rng, &q).unwrap();
        let x_pub = ECPoint::<Secp256k1>::scalar_base_mult(&x_priv);
        let session = b"test_session_zkp";

        // 1. Create proof
        let proof = ZkProof::new(session, &x_priv, &x_pub, &mut rng).unwrap();

        // 2. Verify proof
        assert!(proof.verify(session, &x_pub), "ZKProof verification failed");

        // 3. Verify failure with wrong session
        assert!(!proof.verify(b"wrong_session", &x_pub), "ZKProof verification succeeded with wrong session");

        // 4. Verify failure with wrong public key X
        let x_priv_wrong = get_random_positive_int(&mut rng, &q).unwrap();
        let x_pub_wrong = ECPoint::<Secp256k1>::scalar_base_mult(&x_priv_wrong);
        assert!(!proof.verify(session, &x_pub_wrong), "ZKProof verification succeeded with wrong X");

        // 5. Verify failure with tampered proof `t`
        let mut tampered_proof_t = proof.clone();
        tampered_proof_t.t += BigInt::one();
        assert!(!tampered_proof_t.verify(session, &x_pub), "ZKProof verification succeeded with tampered t");

         // 6. Verify failure with tampered proof `alpha`
         let mut tampered_proof_alpha = proof.clone();
         let random_scalar = get_random_positive_int(&mut rng, &q).unwrap();
         let random_point = ECPoint::<Secp256k1>::scalar_base_mult(&random_scalar);
         tampered_proof_alpha.alpha = tampered_proof_alpha.alpha.add(&random_point).unwrap();
         assert!(!tampered_proof_alpha.verify(session, &x_pub), "ZKProof verification succeeded with tampered alpha");
    }

    #[test]
    fn test_zkv_proof_verify() {
        let mut rng = thread_rng();
        let q = get_k256_q();
        let g = ECPoint::<Secp256k1>::generator();

        // Setup: secrets s, l
        let s = get_random_positive_int(&mut rng, &q).unwrap();
        let l = get_random_positive_int(&mut rng, &q).unwrap();

        // Public points R (random), V = R^s * g^l
        let r_priv = get_random_positive_int(&mut rng, &q).unwrap();
        let r_pub = ECPoint::<Secp256k1>::scalar_base_mult(&r_priv);
        let rs = r_pub.scalar_mul(&s);
        let gl = g.scalar_mul(&l);
        let v_pub = rs.add(&gl).unwrap();

        let session = b"test_session_zkv";

        // 1. Create proof
        let proof = ZkvProof::new(session, &s, &l, &v_pub, &r_pub, &mut rng).unwrap();

        // 2. Verify proof
        assert!(proof.verify(session, &v_pub, &r_pub), "ZKVProof verification failed");

        // 3. Verify failure with wrong session
        assert!(!proof.verify(b"wrong_session", &v_pub, &r_pub), "ZKVProof verification succeeded with wrong session");

        // 4. Verify failure with wrong public key V
        let s_wrong = get_random_positive_int(&mut rng, &q).unwrap();
        let rs_wrong = r_pub.scalar_mul(&s_wrong);
        let v_pub_wrong = rs_wrong.add(&gl).unwrap();
        assert!(!proof.verify(session, &v_pub_wrong, &r_pub), "ZKVProof verification succeeded with wrong V");

        // 5. Verify failure with wrong public key R
        let r_priv_wrong = get_random_positive_int(&mut rng, &q).unwrap();
        let r_pub_wrong = ECPoint::<Secp256k1>::scalar_base_mult(&r_priv_wrong);
        assert!(!proof.verify(session, &v_pub, &r_pub_wrong), "ZKVProof verification succeeded with wrong R");

        // 6. Verify failure with tampered proof `t`
        let mut tampered_proof_t = proof.clone();
        tampered_proof_t.t += BigInt::one();
        assert!(!tampered_proof_t.verify(session, &v_pub, &r_pub), "ZKVProof verification succeeded with tampered t");

        // 7. Verify failure with tampered proof `u`
        let mut tampered_proof_u = proof.clone();
        tampered_proof_u.u += BigInt::one();
        assert!(!tampered_proof_u.verify(session, &v_pub, &r_pub), "ZKVProof verification succeeded with tampered u");

         // 8. Verify failure with tampered proof `alpha`
         let mut tampered_proof_alpha = proof.clone();
         let random_scalar = get_random_positive_int(&mut rng, &q).unwrap();
         let random_point = ECPoint::<Secp256k1>::scalar_base_mult(&random_scalar);
         tampered_proof_alpha.alpha = tampered_proof_alpha.alpha.add(&random_point).unwrap();
 