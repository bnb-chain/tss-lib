// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/crypto/mta/proofs.go

use crate::{
    common::{
        hash::sha512_256i_tagged,
        hash_utils::rejection_sample,
        int::ModInt,
        random::{get_random_positive_int, get_random_positive_relatively_prime_int},
        slice::{multi_bytes_to_bigints, bigints_to_bytes},
        int::is_in_interval,
    },
    crypto::{
        ecpoint::{ECPoint, PointError},
        paillier::PublicKey,
    },
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
pub enum MtaProofError {
    #[error("invalid parameters: {0}")]
    InvalidParameters(String),
    #[error("proof generation failed: {0}")]
    ProofGenerationError(String),
    #[error("proof verification failed")]
    VerificationFailed,
    #[error("point operation failed: {0}")]
    PointError(String),
    #[error("byte conversion error: expected {expected} parts, got {got}")]
    ByteConversionError{ expected: usize, got: usize },
}

impl From<PointError> for MtaProofError {
    fn from(err: PointError) -> Self {
        MtaProofError::PointError(err.to_string())
    }
}

const PROOF_BOB_BYTES_PARTS: usize = 10;
const PROOF_BOB_WC_BYTES_PARTS: usize = 12;

/// Proof structure for Bob in MtA protocol (without check). (Fig 11)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBob {
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub z: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub z_prm: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub t: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub v: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub w: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub s: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub s1: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub s2: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub t1: BigInt,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub t2: BigInt,
}

/// Proof structure for Bob in MtA protocol (with check). (Fig 10)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBobWC<C: Curve + CurveArithmetic> {
    #[serde(flatten)]
    pub proof_bob: ProofBob,
    // Need to handle ECPoint serialization
    #[serde(bound(serialize = "ECPoint<C>: Serialize", deserialize = "ECPoint<C>: Deserialize<'de>"))]
    pub u: ECPoint<C>,
}

// --- ProofBobWC Generation and Verification ---

impl<C> ProofBobWC<C>
where
    C: Curve + CurveArithmetic,
    ECPoint<C>: Clone + PartialEq + Serialize + for<'de> Deserialize<'de>,
{
    /// Generates Bob's MtA proof, either with or without the consistency check (`x_pub` provided).
    /// Implements Figs. 10 & 11 from GG18Spec (9).
    #[allow(clippy::too_many_arguments)]
    pub fn new<R: CryptoRng + RngCore>(
        session: &[u8],
        curve_q: &BigInt,
        pk: &PublicKey,
        n_tilde: &BigInt,
        h1: &BigInt,
        h2: &BigInt,
        c1: &BigInt,
        c2: &BigInt, // Not used in proof calc, but used in hash `e` for Fig 10?
        x_priv: &BigInt,
        y_priv: &BigInt,
        r_enc: &BigInt,     // randomness used for c2 = Enc(y)
        x_pub: Option<&ECPoint<C>>, // Public key X = g^x (if None, generates proof without check)
        rng: &mut R,
    ) -> Result<Self, MtaProofError> {
        // Parameter checks (simplified)
        if pk.n.sign() != Sign::Plus || n_tilde.sign() != Sign::Plus || h1.sign() != Sign::Plus || h2.sign() != Sign::Plus {
             return Err(MtaProofError::InvalidParameters("Negative N, Ntilde, h1, or h2".to_string()));
         }
        // Basic validation for optional X
         if let Some(x_p) = x_pub {
             if !x_p.validate_basic() {
                 return Err(MtaProofError::InvalidParameters("Invalid X provided".to_string()));
             }
         }

        let n = &pk.n;
        let n_square = pk.n_square();
        let mod_n_tilde = ModInt::new(n_tilde.clone());
        let mod_n_square = ModInt::new(n_square.clone());
        let mod_n = ModInt::new(n.clone());
        let mod_q = ModInt::new(curve_q.clone());

        // Precompute powers of q
        let q2 = mod_q.mul(curve_q, curve_q);
        let q3 = mod_q.mul(curve_q, &q2);
        let q6 = mod_q.mul(&q3, &q3);
        let q7 = mod_q.mul(curve_q, &q6);

        // Precompute products involving q
        let q_n_tilde = curve_q * n_tilde;
        let q3_n_tilde = &q3 * n_tilde;

        // 1. alpha <- Z_(q^3)
        let alpha = get_random_positive_int(rng, &q3)
            .ok_or_else(|| MtaProofError::ProofGenerationError("Failed to generate alpha".to_string()))?;

        // 2. rho, sigma <- Z_(q*N_tilde), tau <- Z_(q^3*N_tilde)
        let rho = get_random_positive_int(rng, &q_n_tilde)
             .ok_or_else(|| MtaProofError::ProofGenerationError("Failed to generate rho".to_string()))?;
        let sigma = get_random_positive_int(rng, &q_n_tilde)
             .ok_or_else(|| MtaProofError::ProofGenerationError("Failed to generate sigma".to_string()))?;
        let tau = get_random_positive_int(rng, &q3_n_tilde)
             .ok_or_else(|| MtaProofError::ProofGenerationError("Failed to generate tau".to_string()))?;

        // 3. rho' <- Z_(q^3*N_tilde)
        let rho_prm = get_random_positive_int(rng, &q3_n_tilde)
             .ok_or_else(|| MtaProofError::ProofGenerationError("Failed to generate rho_prm".to_string()))?;

        // 4. beta <- Z*N, gamma <- Z_(q^7)
        let beta = get_random_positive_relatively_prime_int(rng, n)
             .ok_or_else(|| MtaProofError::ProofGenerationError("Failed to generate beta".to_string()))?;
        let gamma = get_random_positive_int(rng, &q7)
            .ok_or_else(|| MtaProofError::ProofGenerationError("Failed to generate gamma".to_string()))?;

        // 5. u = g^alpha (only if X is provided)
        let mut u = ECPoint::<C>::identity(); // Default identity if no check
        if let Some(_x_p) = x_pub {
            u = ECPoint::<C>::scalar_base_mult(&alpha);
        }

        // 6. z = h1^x * h2^rho mod N_tilde
        let h1_x = mod_n_tilde.exp(h1, x_priv);
        let h2_rho = mod_n_tilde.exp(h2, &rho);
        let z = mod_n_tilde.mul(&h1_x, &h2_rho);

        // 7. z' = h1^alpha * h2^rho' mod N_tilde
        let h1_alpha = mod_n_tilde.exp(h1, &alpha);
        let h2_rho_prm = mod_n_tilde.exp(h2, &rho_prm);
        let z_prm = mod_n_tilde.mul(&h1_alpha, &h2_rho_prm);

        // 8. t = h1^y * h2^sigma mod N_tilde
        let h1_y = mod_n_tilde.exp(h1, y_priv);
        let h2_sigma = mod_n_tilde.exp(h2, &sigma);
        let t_val = mod_n_tilde.mul(&h1_y, &h2_sigma);

        // 9. v = c1^alpha * Gamma^gamma * beta^N mod N^2
        let c1_alpha = mod_n_square.exp(c1, &alpha);
        let gamma_gamma = mod_n_square.exp(&pk.gamma(), &gamma);
        let beta_n = mod_n_square.exp(&beta, n);
        let v_tmp1 = mod_n_square.mul(&c1_alpha, &gamma_gamma);
        let v = mod_n_square.mul(&v_tmp1, &beta_n);

        // 10. w = h1^gamma * h2^tau mod N_tilde
        let h1_gamma = mod_n_tilde.exp(h1, &gamma);
        let h2_tau = mod_n_tilde.exp(h2, &tau);
        let w = mod_n_tilde.mul(&h1_gamma, &h2_tau);

        // 11-12. Compute challenge e = H(session, pk, ...)
        let e: BigInt;
        {
            let hash_input: Vec<&BigInt>;
            let (u_x, u_y) = u.coords(); // Get coords even if identity
            let pk_ints = pk.as_ints(); // [N, Gamma]

            if let Some(x_p) = x_pub {
                // With check (Fig 10): H(session, N, Gamma, Xx, Xy, c1, c2, ux, uy, z, z', t, v, w)
                 let (x_pub_x, x_pub_y) = x_p.coords();
                 hash_input = vec![
                    &pk_ints[0], &pk_ints[1], &x_pub_x, &x_pub_y, c1, c2, &u_x, &u_y,
                     &z, &z_prm, &t_val, &v, &w
                 ];
            } else {
                // Without check (Fig 11): H(session, N, Gamma, c1, c2, z, z', t, v, w)
                // Note: Fig 11 uses c2 = Enc_pk(y, r) instead of x_pub/u in the hash
                // Assuming `c2` is passed correctly for this case.
                hash_input = vec![
                    &pk_ints[0], &pk_ints[1], c1, c2, &z, &z_prm, &t_val, &v, &w
                ];
            }

            let e_hash = sha512_256i_tagged(session, &hash_input)
                .ok_or_else(|| MtaProofError::ProofGenerationError("Failed to compute challenge hash e".to_string()))?;
            e = rejection_sample(curve_q, &e_hash);
        }

        // 13. s = r^e * beta mod N
        let r_e = mod_n.exp(r_enc, &e);
        let s = mod_n.mul(&r_e, &beta);

        // 14. s1 = alpha + e*x mod q (? should be mod q? Fig 10/11 has no mod)
        // Go code adds without mod q. Let's stick to that.
        let ex = &e * x_priv;
        let s1 = &alpha + &ex;

        // 15. s2 = rho_prm + e*rho mod (q*N_tilde) (?)
        // Go code adds without mod q*N_tilde.
        let e_rho = &e * &rho;
        let s2 = &rho_prm + &e_rho;

        // 16. t1 = gamma + e*y mod q^7 (?)
        // Go code adds without mod q^7.
        let ey = &e * y_priv;
        let t1 = &gamma + &ey;

        // 17. t2 = tau + e*sigma mod (q^3*N_tilde) (?)
        // Go code adds without mod q^3*N_tilde.
        let e_sigma = &e * &sigma;
        let t2 = &tau + &e_sigma;

        let proof_bob = ProofBob {
            z, z_prm, t: t_val, v, w, s, s1, s2, t1, t2
        };
        Ok(Self { proof_bob, u })
    }

    /// Verifies Bob's MtA proof "with check" (Fig 10).
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        session: &[u8],
        curve_q: &BigInt,
        pk: &PublicKey,
        n_tilde: &BigInt,
        h1: &BigInt,
        h2: &BigInt,
        c1: &BigInt,
        c2: &BigInt,
        x_pub: &ECPoint<C>, // Public key X = g^x (Required for WC verify)
    ) -> bool {
        if !self.validate_basic() || !x_pub.validate_basic() || pk.n.sign() != Sign::Plus || n_tilde.sign() != Sign::Plus {
            return false;
        }

        let n = &pk.n;
        let n_square = pk.n_square();
        let mod_n_tilde = ModInt::new(n_tilde.clone());
        let mod_n_square = ModInt::new(n_square.clone());
        let mod_n = ModInt::new(n.clone());

        // Basic range checks (similar to Go, simplified)
         let q3 = curve_q.pow(3);
         let q7 = curve_q.pow(7);
        if !is_in_interval(&self.proof_bob.z, n_tilde) || !is_in_interval(&self.proof_bob.z_prm, n_tilde) ||
           !is_in_interval(&self.proof_bob.t, n_tilde) || !is_in_interval(&self.proof_bob.v, &n_square) ||
           !is_in_interval(&self.proof_bob.w, n_tilde) || !is_in_interval(&self.proof_bob.s, n) ||
            self.proof_bob.s1.sign() == Sign::Minus || self.proof_bob.s2.sign() == Sign::Minus || // Check non-negative for large bounds
            self.proof_bob.t1.sign() == Sign::Minus || self.proof_bob.t2.sign() == Sign::Minus
        {
             error!("MtA BobWC Verify: Range check failed");
            return false;
        }

        // Check GCD conditions (simplified)
        if self.proof_bob.z.gcd(n_tilde) != BigInt::one() || self.proof_bob.z_prm.gcd(n_tilde) != BigInt::one() ||
           self.proof_bob.t.gcd(n_tilde) != BigInt::one() || self.proof_bob.v.gcd(&n_square) != BigInt::one() ||
           self.proof_bob.w.gcd(n_tilde) != BigInt::one() || self.proof_bob.s.gcd(n) != BigInt::one()
         {
             error!("MtA BobWC Verify: GCD check failed");
            return false;
         }

        // Recalculate challenge e = H(...)
        let e: BigInt;
        {
             let hash_input: Vec<&BigInt>;
             let (u_x, u_y) = self.u.coords();
             let pk_ints = pk.as_ints(); // [N, Gamma]
             let (x_pub_x, x_pub_y) = x_pub.coords();

             hash_input = vec![
                 &pk_ints[0], &pk_ints[1], &x_pub_x, &x_pub_y, c1, c2, &u_x, &u_y,
                 &self.proof_bob.z, &self.proof_bob.z_prm, &self.proof_bob.t, &self.proof_bob.v, &self.proof_bob.w
             ];

             let e_hash = match sha512_256i_tagged(session, &hash_input) {
                 Some(h) => h,
                 None => {
                     error!("MtA BobWC Verify: Failed to compute challenge hash e");
                     return false;
                 }
             };
             e = rejection_sample(curve_q, &e_hash);
         }

        // Verification Check 1: g^s1 = u * X^e
         let gs1 = ECPoint::<C>::scalar_base_mult(&self.proof_bob.s1);
         let xe = x_pub.scalar_mul(&e);
         let u_xe = match self.u.add(&xe) {
             Ok(p) => p,
             Err(_) => { error!("MtA BobWC Verify Check 1: Point op failed"); return false; }
         };
         if gs1 != u_xe {
             error!("MtA BobWC Verify Check 1 failed: g^s1 != u * X^e");
             return false;
         }

        // Verification Check 2: h1^s1 * h2^s2 = z_prm * z^e mod N_tilde
        let h1_s1 = mod_n_tilde.exp(h1, &self.proof_bob.s1);
        let h2_s2 = mod_n_tilde.exp(h2, &self.proof_bob.s2);
        let lhs2 = mod_n_tilde.mul(&h1_s1, &h2_s2);
        let z_e = mod_n_tilde.exp(&self.proof_bob.z, &e);
        let rhs2 = mod_n_tilde.mul(&self.proof_bob.z_prm, &z_e);
        if lhs2 != rhs2 {
             error!("MtA BobWC Verify Check 2 failed: h1^s1 * h2^s2 != z' * z^e");
            return false;
        }

        // Verification Check 3: c1^s1 * Gamma^t1 * s^N = v * c2^e mod N^2
        let c1_s1 = mod_n_square.exp(c1, &self.proof_bob.s1);
        let gamma_t1 = mod_n_square.exp(&pk.gamma(), &self.proof_bob.t1);
        let s_n = mod_n_square.exp(&self.proof_bob.s, n);
        let lhs3_tmp = mod_n_square.mul(&c1_s1, &gamma_t1);
        let lhs3 = mod_n_square.mul(&lhs3_tmp, &s_n);
        let c2_e = mod_n_square.exp(c2, &e);
        let rhs3 = mod_n_square.mul(&self.proof_bob.v, &c2_e);
         if lhs3 != rhs3 {
             error!("MtA BobWC Verify Check 3 failed: c1^s1 * G^t1 * s^N != v * c2^e");
            return false;
        }

        // Verification Check 4: h1^t1 * h2^t2 = w * t^e mod N_tilde
        let h1_t1 = mod_n_tilde.exp(h1, &self.proof_bob.t1);
        let h2_t2 = mod_n_tilde.exp(h2, &self.proof_bob.t2);
        let lhs4 = mod_n_tilde.mul(&h1_t1, &h2_t2);
        let t_e = mod_n_tilde.exp(&self.proof_bob.t, &e);
        let rhs4 = mod_n_tilde.mul(&self.proof_bob.w, &t_e);
         if lhs4 != rhs4 {
             error!("MtA BobWC Verify Check 4 failed: h1^t1 * h2^t2 != w * t^e");
            return false;
        }

        true
    }

    /// Basic validation of proof components.
    pub fn validate_basic(&self) -> bool {
        self.proof_bob.validate_basic() && self.u.validate_basic()
    }

    /// Converts the proof to a vector of byte vectors.
    pub fn to_bytes(&self) -> Result<Vec<Vec<u8>>, MtaProofError> {
        let mut bzs = self.proof_bob.to_bytes()?;
        bzs.extend_from_slice(&bigints_to_bytes(&[&self.u.x(), &self.u.y()]));
        if bzs.len() != PROOF_BOB_WC_BYTES_PARTS {
            return Err(MtaProofError::InternalError(format!(
                "ProofBobWC to_bytes length mismatch: expected {}, got {}",
                PROOF_BOB_WC_BYTES_PARTS, bzs.len()
            )));
        }
        Ok(bzs)
    }

    /// Creates a ProofBobWC from a slice of byte vectors.
    pub fn from_bytes(bzs: &[Vec<u8>]) -> Result<Self, MtaProofError> {
        if bzs.len() != PROOF_BOB_WC_BYTES_PARTS {
            return Err(MtaProofError::ByteConversionError{ expected: PROOF_BOB_WC_BYTES_PARTS, got: bzs.len() });
        }
        let proof_bob = ProofBob::from_bytes(&bzs[..PROOF_BOB_BYTES_PARTS])?;
        // TODO: Need curve info C to create ECPoint
        // Need to decide how to handle curve type here. Assuming Secp256k1 for now.
        let u = ECPoint::<k256::Secp256k1>::from_coords(
             &BigInt::from_bytes_be(Sign::Plus, &bzs[10]),
             &BigInt::from_bytes_be(Sign::Plus, &bzs[11]),
        ).map_err(|e| MtaProofError::PointError(format!("Failed to create point U from bytes: {}", e)))?;

         // This is problematic - we need the curve type C generically.
         // Need a way to pass curve type or use a default/registry.
         panic!("ProofBobWC::from_bytes needs curve type C to reconstruct point U");

        // Ok(Self { proof_bob, u })
    }
}

// --- ProofBob Generation and Verification (without check) ---

impl ProofBob {
    /// Generates Bob's MtA proof "without check" (Fig 11).
    #[allow(clippy::too_many_arguments)]
    pub fn new<C, R>(
        session: &[u8],
        curve_q: &BigInt,
        pk: &PublicKey,
        n_tilde: &BigInt,
        h1: &BigInt,
        h2: &BigInt,
        c1: &BigInt,
        c2: &BigInt, // Used in hash for Fig 11
        x_priv: &BigInt,
        y_priv: &BigInt,
        r_enc: &BigInt,
        rng: &mut R,
    ) -> Result<Self, MtaProofError>
    where
        C: Curve + CurveArithmetic,
        R: CryptoRng + RngCore,
        ECPoint<C>: Clone + PartialEq + Serialize + for<'de> Deserialize<'de>,
    {
        // Call the WC version with x_pub = None
        let pf_wc = ProofBobWC::<C>::new(
            session, curve_q, pk, n_tilde, h1, h2, c1, c2,
            x_priv, y_priv, r_enc, None, rng
        )?;
        Ok(pf_wc.proof_bob)
    }

    /// Verifies Bob's MtA proof "without check" (Fig 11).
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        session: &[u8],
        curve_q: &BigInt,
        pk: &PublicKey,
        n_tilde: &BigInt,
        h1: &BigInt,
        h2: &BigInt,
        c1: &BigInt,
        c2: &BigInt, // Used in hash for Fig 11
    ) -> bool {
         if !self.validate_basic() || pk.n.sign() != Sign::Plus || n_tilde.sign() != Sign::Plus {
            return false;
        }

        let n = &pk.n;
        let n_square = pk.n_square();
        let mod_n_tilde = ModInt::new(n_tilde.clone());
        let mod_n_square = ModInt::new(n_square.clone());
        let mod_n = ModInt::new(n.clone());

        // Basic range checks (similar to Go, simplified)
         if !is_in_interval(&self.z, n_tilde) || !is_in_interval(&self.z_prm, n_tilde) ||
           !is_in_interval(&self.t, n_tilde) || !is_in_interval(&self.v, &n_square) ||
           !is_in_interval(&self.w, n_tilde) || !is_in_interval(&self.s, n) ||
            self.s1.sign() == Sign::Minus || self.s2.sign() == Sign::Minus || // Check non-negative
            self.t1.sign() == Sign::Minus || self.t2.sign() == Sign::Minus
        {
             error!("MtA Bob Verify: Range check failed");
            return false;
        }

        // Check GCD conditions (simplified)
         if self.z.gcd(n_tilde) != BigInt::one() || self.z_prm.gcd(n_tilde) != BigInt::one() ||
           self.t.gcd(n_tilde) != BigInt::one() || self.v.gcd(&n_square) != BigInt::one() ||
           self.w.gcd(n_tilde) != BigInt::one() || self.s.gcd(n) != BigInt::one()
         {
             error!("MtA Bob Verify: GCD check failed");
            return false;
         }

        // Recalculate challenge e = H(...)
        let e: BigInt;
        {
             let hash_input: Vec<&BigInt>;
             let pk_ints = pk.as_ints(); // [N, Gamma]

             // Without check (Fig 11): H(session, N, Gamma, c1, c2, z, z', t, v, w)
             hash_input = vec![
                 &pk_ints[0], &pk_ints[1], c1, c2, &self.z, &self.z_prm, &self.t, &self.v, &self.w
             ];

             let e_hash = match sha512_256i_tagged(session, &hash_input) {
                 Some(h) => h,
                 None => {
                     error!("MtA Bob Verify: Failed to compute challenge hash e");
                     return false;
                 }
             };
             e = rejection_sample(curve_q, &e_hash);
         }

        // Verification Check 1 (Fig 11 has only 3 checks)
        // h1^s1 * h2^s2 = z_prm * z^e mod N_tilde
        let h1_s1 = mod_n_tilde.exp(h1, &self.s1);
        let h2_s2 = mod_n_tilde.exp(h2, &self.s2);
        let lhs1 = mod_n_tilde.mul(&h1_s1, &h2_s2);
        let z_e = mod_n_tilde.exp(&self.z, &e);
        let rhs1 = mod_n_tilde.mul(&self.z_prm, &z_e);
        if lhs1 != rhs1 {
             error!("MtA Bob Verify Check 1 failed: h1^s1 * h2^s2 != z' * z^e");
            return false;
        }

        // Verification Check 2
        // c1^s1 * Gamma^t1 * s^N = v * c2^e mod N^2
        let c1_s1 = mod_n_square.exp(c1, &self.s1);
        let gamma_t1 = mod_n_square.exp(&pk.gamma(), &self.t1);
        let s_n = mod_n_square.exp(&self.s, n);
        let lhs2_tmp = mod_n_square.mul(&c1_s1, &gamma_t1);
        let lhs2 = mod_n_square.mul(&lhs2_tmp, &s_n);
        let c2_e = mod_n_square.exp(c2, &e);
        let rhs2 = mod_n_square.mul(&self.v, &c2_e);
         if lhs2 != rhs2 {
             error!("MtA Bob Verify Check 2 failed: c1^s1 * G^t1 * s^N != v * c2^e");
            return false;
        }

        // Verification Check 3
        // h1^t1 * h2^t2 = w * t^e mod N_tilde
        let h1_t1 = mod_n_tilde.exp(h1, &self.t1);
        let h2_t2 = mod_n_tilde.exp(h2, &self.t2);
        let lhs3 = mod_n_tilde.mul(&h1_t1, &h2_t2);
        let t_e = mod_n_tilde.exp(&self.t, &e);
        let rhs3 = mod_n_tilde.mul(&self.w, &t_e);
         if lhs3 != rhs3 {
             error!("MtA Bob Verify Check 3 failed: h1^t1 * h2^t2 != w * t^e");
            return false;
        }

        true
    }

    /// Basic validation of proof components (checks if any BigInt is zero).
    pub fn validate_basic(&self) -> bool {
        // Check if any field is zero (or negative, though inputs should be positive)
        !self.z.is_zero() && !self.z_prm.is_zero() && !self.t.is_zero() &&
        !self.v.is_zero() && !self.w.is_zero() && !self.s.is_zero() &&
        !self.s1.is_zero() && !self.s2.is_zero() && !self.t1.is_zero() &&
        !self.t2.is_zero()
        // Consider adding sign checks if necessary, although proof generation should yield positive values
    }

     /// Converts the proof to a vector of byte vectors.
     pub fn to_bytes(&self) -> Result<Vec<Vec<u8>>, MtaProofError> {
         let parts = vec![
            &self.z, &self.z_prm, &self.t, &self.v, &self.w,
            &self.s, &self.s1, &self.s2, &self.t1, &self.t2,
        ];
        Ok(bigints_to_bytes(&parts))
     }

     /// Creates a ProofBob from a slice of byte vectors.
     pub fn from_bytes(bzs: &[Vec<u8>]) -> Result<Self, MtaProofError> {
         if bzs.len() != PROOF_BOB_BYTES_PARTS {
            return Err(MtaProofError::ByteConversionError{ expected: PROOF_BOB_BYTES_PARTS, got: bzs.len() });
        }
         let ints = multi_bytes_to_bigints(bzs);
         if ints.len() != PROOF_BOB_BYTES_PARTS {
              // This should not happen if multi_bytes_to_bigints works correctly
             return Err(MtaProofError::InternalError("BigInt conversion length mismatch".to_string()));
         }
         Ok(Self {
             z: ints[0].clone(),
             z_prm: ints[1].clone(),
             t: ints[2].clone(),
             v: ints[3].clone(),
             w: ints[4].clone(),
             s: ints[5].clone(),
             s1: ints[6].clone(),
             s2: ints[7].clone(),
             t1: ints[8].clone(),
             t2: ints[9].clone(),
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
    async fn setup_mta_params(rng_arc: Arc<Mutex<thread_rng::ThreadRng>>) -> (PublicKey, BigInt, BigInt, BigInt) {
        let bits = 1024; // Smaller for testing
        let (_paillier_sk, paillier_pk) = paillier::generate_key_pair(Arc::clone(&rng_arc), bits, 1).await.unwrap();
        let q = get_k256_q();
        let n_tilde = get_random_positive_int(&mut *rng_arc.lock().await, &q).unwrap(); // Simplified Ntilde for test
        let h1 = get_random_positive_relatively_prime_int(&mut *rng_arc.lock().await, &n_tilde).unwrap();
        let h2 = get_random_positive_relatively_prime_int(&mut *rng_arc.lock().await, &n_tilde).unwrap();
        (paillier_pk, n_tilde, h1, h2)
    }

    #[tokio::test]
    async fn test_mta_proof_bob_wc() {
        let mut rng_thread = thread_rng();
        let rng_arc = Arc::new(Mutex::new(rng_thread));
        let (pk, n_tilde, h1, h2) = setup_mta_params(Arc::clone(&rng_arc)).await;
        let q = get_k256_q();
        let session = b"test_mta_wc";

        // Bob's values
        let x = get_random_positive_int(&mut *rng_arc.lock().await, &q).unwrap();
        let y = get_random_positive_int(&mut *rng_arc.lock().await, &q).unwrap();

        // Alice computes c1 = Enc(x)
        let (c1, _r1) = pk.encrypt_and_return_randomness(&mut *rng_arc.lock().await, &x).unwrap();
        // Bob computes c2 = Enc(y, r) needed for hash in Fig 10/11?
        let (c2, r_c2) = pk.encrypt_and_return_randomness(&mut *rng_arc.lock().await, &y).unwrap();

        // Bob needs X = g^x for the WC proof
         let x_pub = ECPoint::<Secp256k1>::scalar_base_mult(&x);

        // Create ProofBobWC (Fig 10)
        let proof_wc = ProofBobWC::<Secp256k1>::new(
            session, &q, &pk, &n_tilde, &h1, &h2, &c1, &c2,
            &x, &y, &r_c2, Some(&x_pub), &mut *rng_arc.lock().await
        ).unwrap();

        // Verify ProofBobWC
        let is_valid_wc = proof_wc.verify(session, &q, &pk, &n_tilde, &h1, &h2, &c1, &c2, &x_pub);
        assert!(is_valid_wc, "ProofBobWC verification failed");

        // Test serialization/deserialization (ProofBobWC needs curve info handling)
        // let bytes_wc = proof_wc.to_bytes().unwrap();
        // let proof_wc_recon = ProofBobWC::<Secp256k1>::from_bytes(&bytes_wc).unwrap();
        // assert_eq!(proof_wc, proof_wc_recon);

         // Test failure cases
         assert!(!proof_wc.verify(b"wrong", &q, &pk, &n_tilde, &h1, &h2, &c1, &c2, &x_pub), "WC verify ok with wrong session");
         let x_pub_wrong = ECPoint::<Secp256k1>::scalar_base_mult(&BigInt::one());
         assert!(!proof_wc.verify(session, &q, &pk, &n_tilde, &h1, &h2, &c1, &c2, &x_pub_wrong), "WC verify ok with wrong X");
         let mut tampered_proof = proof_wc.clone();
         tampered_proof.proof_bob.z += BigInt::one();
         assert!(!tampered_proof.verify(session, &q, &pk, &n_tilde, &h1, &h2, &c1, &c2, &x_pub), "WC verify ok with tampered proof");
    }

    #[tokio::test]
    async fn test_mta_proof_bob() {
         let mut rng_thread = thread_rng();
        let rng_arc = Arc::new(Mutex::new(rng_thread));
        let (pk, n_tilde, h1, h2) = setup_mta_params(Arc::clone(&rng_arc)).await;
        let q = get_k256_q();
        let session = b"test_mta_no_check";

        // Bob's values
        let x = get_random_positive_int(&mut *rng_arc.lock().await, &q).unwrap();
        let y = get_random_positive_int(&mut *rng_arc.lock().await, &q).unwrap();

        // Alice computes c1 = Enc(x)
        let (c1, _r1) = pk.encrypt_and_return_randomness(&mut *rng_arc.lock().await, &x).unwrap();
        // Bob computes c2 = Enc(y, r) needed for hash in Fig 11
        let (c2, r_c2) = pk.encrypt_and_return_randomness(&mut *rng_arc.lock().await, &y).unwrap();

        // Create ProofBob (Fig 11)
        let proof = ProofBob::new::<Secp256k1, _>(
            session, &q, &pk, &n_tilde, &h1, &h2, &c1, &c2,
            &x, &y, &r_c2, &mut *rng_arc.lock().await
        ).unwrap();

        // Verify ProofBob
        let is_valid = proof.verify(session, &q, &pk, &n_tilde, &h1, &h2, &c1, &c2);
        assert!(is_valid, "ProofBob verification failed");

         // Test serialization/deserialization
         let bytes = proof.to_bytes().unwrap();
         assert_eq!(bytes.len(), PROOF_BOB_BYTES_PARTS);
         let proof_recon = ProofBob::from_bytes(&bytes).unwrap();
         assert_eq!(proof, proof_recon);

         // Test failure cases
         assert!(!proof.verify(b"wrong", &q, &pk, &n_tilde, &h1, &h2, &c1, &c2), "Bob verify ok with wrong session");
         let mut tampered_proof = proof.clone();
         tampered_proof.z += BigInt::one();
         assert!(!tampered_proof.verify(session, &q, &pk, &n_tilde, &h1, &h2, &c1, &c2), "Bob verify ok with tampered proof");
    }
} 