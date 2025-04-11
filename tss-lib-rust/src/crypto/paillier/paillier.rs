// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/crypto/paillier/paillier.go
// Implementation adheres to GG18Spec (6)

use crate::{
    common::{
        hash::sha512_256i,
        random::*,
        safe_prime::get_random_safe_primes_concurrent,
        int::ModInt,
    },
    crypto::ecpoint::{ECPoint, PointError}, // Assuming generic ECPoint
    tss::Curve, // Assuming a way to get the curve type (e.g., Secp256k1)
};

use num_bigint_dig::{BigInt, RandBigInt, Sign};
use num_integer::Integer;
use num_prime::nt_funcs;
use num_traits::{Zero, One, FromPrimitive, ToPrimitive};
use rand::{CryptoRng, RngCore};
use thiserror::Error;
use std::sync::Arc;
use tokio::sync::Mutex;
use log::{error, debug};
use serde::{Serialize, Deserialize};

// Using K256 curve for proof generation as an example. Needs adjustment if different curves are used.
use k256::Secp256k1;

pub const PROOF_ITERS: usize = 13; // Matches Go code
const VERIFY_PRIMES_UNTIL: u64 = 1000; // Matches Go code
const PQ_BIT_LEN_DIFFERENCE: u32 = 3; // Matches Go code

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PaillierError {
    #[error("message is too large or < 0")]
    MessageTooLong,
    #[error("message is malformed (gcd(c, N^2) != 1)")]
    MessageMalformed,
    #[error("key generation failed: {0}")]
    KeyGenerationError(String),
    #[error("proof verification failed: {0}")]
    ProofVerificationError(String),
    #[error("internal crypto error: {0}")]
    InternalCryptoError(String),
    #[error("failed to get lock on RNG: {0}")]
    RngLockError(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub n: BigInt, // Paillier modulus n = p * q
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKey {
    pub public_key: PublicKey,
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub lambda_n: BigInt, // Carmichael function lambda(n) = lcm(p-1, q-1)
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub phi_n: BigInt,    // Euler's totient function phi(n) = (p-1)(q-1)
    #[serde(skip)] // Do not serialize p, q directly by default
    p: Option<BigInt>,
    #[serde(skip)] // Do not serialize p, q directly by default
    q: Option<BigInt>,
}

/// Paillier ZK proof array.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaillierProof {
     #[serde(with = "crate::serde_support::vec_bigint_bytes")]
     pub proof: Vec<BigInt>, // Fixed size of PROOF_ITERS
}

/// Generates a Paillier key pair (PublicKey, PrivateKey).
/// Uses safe primes `p`, `q` for modulus `n = p * q`.
pub async fn generate_key_pair<R: CryptoRng + RngCore + Send + Sync + 'static>(
    rng: Arc<Mutex<R>>,
    modulus_bit_len: usize,
    concurrency: usize,
) -> Result<(PrivateKey, PublicKey), PaillierError> {
    if modulus_bit_len < 2048 { // Recommendation for security
         log::warn!("Paillier key bit length {} is less than the recommended 2048 bits", modulus_bit_len);
     }

    let prime_bits = modulus_bit_len / 2;
    let p: BigInt;
    let q: BigInt;
    let n: BigInt;

    // Generate two distinct safe primes p, q
    loop {
         // Use the concurrent safe prime generator
         let sgps = get_random_safe_primes_concurrent(prime_bits, 2, concurrency, Arc::clone(&rng))
             .await
             .map_err(|e| PaillierError::KeyGenerationError(format!("Failed to generate safe primes: {}", e)))?;

        p = sgps[0].safe_prime().clone();
        q = sgps[1].safe_prime().clone();

        // Ensure p != q (highly unlikely but good practice)
        if p == q {
            continue;
        }

        // Ensure |p| - |q| is large enough (check bit length difference)
        let diff = p.bits().abs_diff(q.bits());
        let min_diff = prime_bits.saturating_sub(PQ_BIT_LEN_DIFFERENCE as usize);
        // Note: This check might be slightly different from Go's `Sub().BitLen()` if p,q have same bitlen
         if diff >= min_diff || p.bits() < min_diff || q.bits() < min_diff { // If lengths differ enough, or one is small
            n = &p * &q;
            // Final check on N's bit length
            if n.bits() >= modulus_bit_len as u64 {
                 break;
             }
         }
         debug!("Regenerating primes p, q due to bit length difference check failure (diff={}, min_diff={}, p_bits={}, q_bits={})", diff, min_diff, p.bits(), q.bits());
    }

    // phi_n = (p-1)(q-1)
    let p_minus_1 = &p - BigInt::one();
    let q_minus_1 = &q - BigInt::one();
    let phi_n = &p_minus_1 * &q_minus_1;

    // lambda_n = lcm(p-1, q-1) = (p-1)(q-1) / gcd(p-1, q-1)
    let gcd = p_minus_1.gcd(&q_minus_1);
    let lambda_n = &phi_n / &gcd;

    let public_key = PublicKey { n: n.clone() };
    let private_key = PrivateKey {
        public_key: public_key.clone(),
        lambda_n,
        phi_n,
        p: Some(p),
        q: Some(q),
    };

    Ok((private_key, public_key))
}

impl PublicKey {
    /// Encrypts a message `m` using Paillier public key and returns the ciphertext `c`
    /// and the randomness `x` used.
    /// Returns error if `m < 0` or `m >= n`.
    pub fn encrypt_and_return_randomness<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        m: &BigInt,
    ) -> Result<(BigInt, BigInt), PaillierError> {
        if m.sign() == Sign::Minus || m >= &self.n {
            return Err(PaillierError::MessageTooLong);
        }

        // Select random x in (Z/nZ)*
        let x = get_random_positive_relatively_prime_int(rng, &self.n)
            .ok_or(PaillierError::InternalCryptoError("Failed to generate x".to_string()))?;

        let n_square = self.n_square();
        let mod_n_square = ModInt::new(n_square);

        // 1. gamma^m mod N^2 (where gamma = n+1)
        let gm = mod_n_square.exp(&self.gamma(), m);

        // 2. x^n mod N^2
        let xn = mod_n_square.exp(&x, &self.n);

        // 3. c = (gm * xn) mod N^2
        let c = mod_n_square.mul(&gm, &xn);

        Ok((c, x))
    }

    /// Encrypts a message `m` using Paillier public key.
    /// Returns error if `m < 0` or `m >= n`.
    pub fn encrypt<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        m: &BigInt,
    ) -> Result<BigInt, PaillierError> {
        self.encrypt_and_return_randomness(rng, m).map(|(c, _)| c)
    }

    /// Homomorphically multiplies an encrypted value `c1` by a plaintext scalar `m`.
    /// Returns `c1^m mod N^2`.
    /// Returns error if `m` or `c1` are out of range.
    pub fn homo_mult(&self, m: &BigInt, c1: &BigInt) -> Result<BigInt, PaillierError> {
        if m.sign() == Sign::Minus || m >= &self.n {
            return Err(PaillierError::MessageTooLong);
        }
        let n_square = self.n_square();
        if c1.sign() == Sign::Minus || c1 >= &n_square {
            // Ciphertext should be in Z/(N^2)Z
            return Err(PaillierError::MessageTooLong);
        }

        let mod_n_square = ModInt::new(n_square);
        Ok(mod_n_square.exp(c1, m))
    }

    /// Homomorphically adds two encrypted values `c1` and `c2`.
    /// Returns `(c1 * c2) mod N^2`.
    /// Returns error if `c1` or `c2` are out of range.
    pub fn homo_add(&self, c1: &BigInt, c2: &BigInt) -> Result<BigInt, PaillierError> {
        let n_square = self.n_square();
         if c1.sign() == Sign::Minus || c1 >= &n_square {
            return Err(PaillierError::MessageTooLong);
        }
        if c2.sign() == Sign::Minus || c2 >= &n_square {
            return Err(PaillierError::MessageTooLong);
        }

        let mod_n_square = ModInt::new(n_square);
        Ok(mod_n_square.mul(c1, c2))
    }

    /// Calculates N^2.
    pub fn n_square(&self) -> BigInt {
        &self.n * &self.n
    }

    /// Returns N+1 (often denoted as `g` or `gamma` in Paillier literature).
    pub fn gamma(&self) -> BigInt {
        &self.n + BigInt::one()
    }

    /// Returns the PublicKey serialised to a slice of BigInts for hashing.
    /// Typically [N, Gamma].
    pub fn as_ints(&self) -> Vec<BigInt> {
        vec![self.n.clone(), self.gamma()]
    }
}

impl PrivateKey {
    /// Decrypts a ciphertext `c` using the Paillier private key.
    /// Returns error if `c` is out of range or malformed (gcd(c, N^2) != 1).
    pub fn decrypt(&self, c: &BigInt) -> Result<BigInt, PaillierError> {
        let n = &self.public_key.n;
        let n_square = self.public_key.n_square();

        if c.sign() == Sign::Minus || c >= &n_square {
            return Err(PaillierError::MessageTooLong);
        }

        // Check gcd(c, n^2) == 1
        if c.gcd(&n_square) != BigInt::one() {
            // Note: Go code checks `Cmp(one) == 1` which means gcd > 1.
            // If gcd is > 1, decryption is invalid.
            return Err(PaillierError::MessageMalformed);
        }

        let mod_n_square = ModInt::new(n_square.clone());
        let mod_n = ModInt::new(n.clone());

        // 1. L(c^lambda mod N^2)
        //    L(u) = (u - 1) / N
        let c_pow_lambda = mod_n_square.exp(c, &self.lambda_n);
        let lc = l_function(&c_pow_lambda, n)?;

        // 2. L(gamma^lambda mod N^2)
        let gamma_pow_lambda = mod_n_square.exp(&self.public_key.gamma(), &self.lambda_n);
        let lg = l_function(&gamma_pow_lambda, n)?;

        // 3. m = (L(c^lambda) * L(gamma^lambda)^-1) mod N
        let lg_inv = mod_n.mod_inverse(&lg)
            .ok_or_else(|| PaillierError::InternalCryptoError(
                 format!("Modular inverse of L(gamma^lambda) does not exist. Lg={}, N={}", lg, n)
            ))?;

        Ok(mod_n.mul(&lc, &lg_inv))
    }

    // Retrieve p and q - only possible if they were stored during generation
    pub fn p(&self) -> Option<&BigInt> {
        self.p.as_ref()
    }
    pub fn q(&self) -> Option<&BigInt> {
        self.q.as_ref()
    }

    /// Generates a Paillier ZK proof using Gennaro et al. method.
    /// Requires an ECDSA public key (as ECPoint) and a challenge `k`.
    /// Note: Assumes ECPoint can provide coordinates.
    pub fn proof<
        C: Curve + CurveArithmetic,
        R: CryptoRng + RngCore
    >(
        &self,
        _rng: &mut R, // rng is not used in Go proof generation, xs derived deterministically
        k: &BigInt,
        ecdsa_pub: &ECPoint<C>,
    ) -> Result<PaillierProof, PaillierError>
    where
         ECPoint<C>: Clone + PartialEq,
         // Add trait bounds needed by ECPoint methods if necessary
    {
        let n = &self.public_key.n;
        let phi_n = &self.phi_n;

        // Calculate M = N^-1 mod PhiN
        let m_inv = n.modinv(phi_n).ok_or_else(|| {
            PaillierError::InternalCryptoError("N^-1 mod PhiN does not exist".to_string())
        })?;

        let xs = generate_xs::<C>(PROOF_ITERS, k, n, ecdsa_pub)?;
        let mut proof_vec = Vec::with_capacity(PROOF_ITERS);
        let mod_n = ModInt::new(n.clone());

        for x_i in xs {
            let pi_i = mod_n.exp(&x_i, &m_inv);
            proof_vec.push(pi_i);
        }

        Ok(PaillierProof { proof: proof_vec })
    }
}

impl PaillierProof {
    /// Verifies a Paillier ZK proof.
    pub fn verify<
        C: Curve + CurveArithmetic,
    >(
        &self,
        pk_n: &BigInt,  // Public key N
        k: &BigInt,     // Challenge
        ecdsa_pub: &ECPoint<C>,
    ) -> Result<bool, PaillierError>
     where
         ECPoint<C>: Clone + PartialEq,
         // Add trait bounds needed by ECPoint methods if necessary
    {
        if self.proof.len() != PROOF_ITERS {
             return Err(PaillierError::ProofVerificationError(
                 format!("Invalid proof length: expected {}, got {}", PROOF_ITERS, self.proof.len())
             ));
         }

        // Check if N is divisible by small primes up to 1000
        // TODO: Consider optimizing prime generation/checking if called frequently
        let small_primes = primes::primes_upto(VERIFY_PRIMES_UNTIL as usize);
        for p_u64 in small_primes {
            let p = BigInt::from(p_u64);
            if pk_n % p == BigInt::zero() {
                debug!("Paillier proof verify: N is divisible by small prime {}", p);
                return Ok(false); // N must not be divisible by small primes
            }
        }

        // Regenerate xs deterministically
        let xs = generate_xs::<C>(PROOF_ITERS, k, pk_n, ecdsa_pub)?;
        if xs.len() != PROOF_ITERS {
             return Err(PaillierError::ProofVerificationError(
                 format!("Internal error: generated xs length mismatch (expected {}, got {})", PROOF_ITERS, xs.len())
             ));
         }

        let mod_n = ModInt::new(pk_n.clone());

        // Check y_i^N = x_i mod N for all i
        for i in 0..PROOF_ITERS {
            let yi = &self.proof[i];
            let xi = &xs[i];

            let yi_exp_n = mod_n.exp(yi, pk_n);
            // Compare yi^N mod N with xi mod N
            // Note: xi should already be < N from generate_xs if using hash correctly
            if yi_exp_n != mod_n.add(xi, &BigInt::zero()) { // Use add(xi, 0) as mod N op
                debug!(
                    "Paillier proof verify failed at iter {}: yi^N ({}) != xi ({}) (mod N)",
                     i, yi_exp_n.to_str_radix(16), xi.to_str_radix(16)
                );
                return Ok(false);
            }
        }

        Ok(true)
    }
}

// --- Helper Functions ---

/// L(u) = (u-1) / n
fn l_function(u: &BigInt, n: &BigInt) -> Result<BigInt, PaillierError> {
    let u_minus_1 = u - BigInt::one();
    // Check if (u-1) is divisible by n
    if &u_minus_1 % n != BigInt::zero() {
         Err(PaillierError::InternalCryptoError(format!(
             "L-function input invalid: (u-1) not divisible by N. u-1={}, N={}", u_minus_1, n
         )))
     } else {
         Ok(u_minus_1 / n)
     }
}

/// Generates challenges `x_i = H(k, N, g, Gx, Gy, i)` for the Paillier ZK proof.
/// Where g = N+1, G = ecdsaPub.
fn generate_xs<
    C: Curve + CurveArithmetic,
>(
    m: usize,       // Number of challenges (PROOF_ITERS)
    k: &BigInt,     // Challenge seed
    n: &BigInt,     // Paillier public key N
    ecdsa_pub: &ECPoint<C>,
) -> Result<Vec<BigInt>, PaillierError>
 where
     ECPoint<C>: Clone + PartialEq,
     // Add trait bounds needed by ECPoint methods if necessary
{
    let g = n + BigInt::one(); // Paillier generator g = N+1
    let (ecdsa_x, ecdsa_y) = ecdsa_pub.coords(); // Needs ECPoint to implement coords()

    let mut xs = Vec::with_capacity(m);
    for i in 0..m {
        let i_big = BigInt::from(i);
        // Hash components: H(k, N, g, Gx, Gy, i)
        let hash_input = vec![k, n, &g, &ecdsa_x, &ecdsa_y, &i_big];
        let x_i = sha512_256i(&hash_input).ok_or_else(|| {
             PaillierError::InternalCryptoError(format!("Failed to generate hash for x_{}", i))
         })?;
        xs.push(x_i);
    }
    Ok(xs)
}

// Need a prime generation library compatible with no_std if necessary
// Using the `primes` crate here which might not be ideal for all contexts.
mod primes {
    use once_cell::sync::Lazy;
    use std::collections::HashSet;

    // Simple prime cache using Lazy static
    static PRIME_CACHE: Lazy<HashSet<u64>> = Lazy::new(|| {
         primal::Primes::all().take(1000).map(|p| p as u64).collect()
     });

    pub fn primes_upto(limit: usize) -> Vec<u64> {
        // Inefficiently filters the cached primes
        // Consider a more direct generation if performance is critical
         let limit_u64 = limit as u64;
         let mut result: Vec<u64> = PRIME_CACHE.iter()
             .filter(|&&p| p <= limit_u64)
             .cloned()
             .collect();
         result.sort_unstable(); // Ensure sorted output
         result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tss::Secp256k1Curve; // Example curve
    use rand::thread_rng;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use elliptic_curve::group::GroupEncoding;
    use k256::ProjectivePoint;

    // Helper to get test key pair
    async fn get_test_keys(bits: usize) -> (PrivateKey, PublicKey) {
        let mut rng = thread_rng();
        let rng_arc = Arc::new(Mutex::new(rng));
        generate_key_pair(rng_arc, bits, 1).await.unwrap()
    }

    #[tokio::test]
    async fn test_paillier_encryption_decryption() {
        let mut rng = thread_rng();
        let (private_key, public_key) = get_test_keys(2048).await;

        let messages = vec![
            BigInt::zero(),
            BigInt::one(),
            BigInt::from(123456u64),
            &public_key.n - BigInt::one(), // Max valid message
        ];

        for m in messages {
            println!("Testing encryption/decryption for message: {}", m);
            let (c, x) = public_key.encrypt_and_return_randomness(&mut rng, &m).unwrap();
            println!("  Ciphertext c: ...{}", c.to_string().chars().take(20).collect::<String>());
            println!("  Randomness x: ...{}", x.to_string().chars().take(20).collect::<String>());

            let decrypted_m = private_key.decrypt(&c).unwrap();
            println!("  Decrypted m: {}", decrypted_m);
            assert_eq!(m, decrypted_m, "Decryption failed for message {}", m);
        }
    }

    #[tokio::test]
    async fn test_paillier_homomorphic_ops() {
        let mut rng = thread_rng();
        let (private_key, public_key) = get_test_keys(2048).await;

        let m1 = BigInt::from(100u64);
        let m2 = BigInt::from(50u64);
        let scalar = BigInt::from(3u64);

        let c1 = public_key.encrypt(&mut rng, &m1).unwrap();
        let c2 = public_key.encrypt(&mut rng, &m2).unwrap();

        // HomoAdd: E(m1) * E(m2) = E(m1 + m2)
        let c_sum = public_key.homo_add(&c1, &c2).unwrap();
        let m_sum = private_key.decrypt(&c_sum).unwrap();
        let expected_sum = (&m1 + &m2) % &public_key.n;
        println!("HomoAdd: Decrypted sum = {}, Expected sum = {}", m_sum, expected_sum);
        assert_eq!(m_sum, expected_sum);

        // HomoMult: E(m1)^scalar = E(m1 * scalar)
        let c_prod = public_key.homo_mult(&scalar, &c1).unwrap();
        let m_prod = private_key.decrypt(&c_prod).unwrap();
        let expected_prod = (&m1 * &scalar) % &public_key.n;
         println!("HomoMult: Decrypted prod = {}, Expected prod = {}", m_prod, expected_prod);
        assert_eq!(m_prod, expected_prod);
    }

    #[tokio::test]
    async fn test_encryption_error_cases() {
         let mut rng = thread_rng();
        let (_private_key, public_key) = get_test_keys(2048).await;

        // Message >= N
        let large_m = &public_key.n;
        let res1 = public_key.encrypt(&mut rng, large_m);
        assert!(matches!(res1, Err(PaillierError::MessageTooLong)));

        // Message < 0
        let neg_m = BigInt::from(-1i64);
        let res2 = public_key.encrypt(&mut rng, &neg_m);
        assert!(matches!(res2, Err(PaillierError::MessageTooLong)));
    }

     #[tokio::test]
    async fn test_decryption_error_cases() {
         let mut rng = thread_rng();
        let (private_key, public_key) = get_test_keys(2048).await;
        let n_sq = public_key.n_square();

        // Ciphertext >= N^2
        let large_c = &n_sq;
        let res1 = private_key.decrypt(large_c);
        assert!(matches!(res1, Err(PaillierError::MessageTooLong)));

         // Ciphertext < 0
        let neg_c = BigInt::from(-1i64);
        let res2 = private_key.decrypt(&neg_c);
        assert!(matches!(res2, Err(PaillierError::MessageTooLong)));

         // Ciphertext not coprime to N^2 (e.g., multiple of p or q)
         // Need p, q from private key
         if let (Some(p), Some(q)) = (private_key.p(), private_key.q()) {
             let c_non_coprime = p; // p is not coprime to N^2 = p^2*q^2
             let res3 = private_key.decrypt(c_non_ coprime);
             // Decryption might proceed but result is meaningless, or fail gcd check
             assert!(matches!(res3, Err(PaillierError::MessageMalformed)), "Decrypt non-coprime failed");

             // Test with a multiple of N
             let c_multiple_n = &public_key.n;
             let res4 = private_key.decrypt(c_multiple_n);
              assert!(matches!(res4, Err(PaillierError::MessageMalformed)), "Decrypt multiple of N failed");
         } else {
             println!("Skipping non-coprime decryption test as p, q are not available");
         }
    }

    #[tokio::test]
    async fn test_paillier_zk_proof() {
         let mut rng = thread_rng();
        let (private_key, public_key) = get_test_keys(1024).await; // Use smaller keys for faster test

        // Generate dummy ECDSA key (using K256 as example)
         let ecdsa_sk = k256::SecretKey::random(&mut rng);
         let ecdsa_pk_k256 = ecdsa_sk.public_key().to_projective();
         let ecdsa_pk_point = ECPoint::<Secp256k1>::from_projective_unchecked(ecdsa_pk_k256);

        // Challenge k
        let k = rng.gen_bigint(256);

        // Generate proof
        let proof = private_key.proof(&mut rng, &k, &ecdsa_pk_point).unwrap();
        assert_eq!(proof.proof.len(), PROOF_ITERS);
        println!("Generated Paillier Proof: {:?}", proof.proof.iter().map(|p| p.to_str_radix(16)).collect::<Vec<_>>());

        // Verify proof
        let is_valid = proof.verify(&public_key.n, &k, &ecdsa_pk_point).unwrap();
        assert!(is_valid, "Paillier proof verification failed");

        // Verification should fail with wrong k
        let wrong_k = k + BigInt::one();
        let is_valid_wrong_k = proof.verify(&public_key.n, &wrong_k, &ecdsa_pk_point).unwrap();
        assert!(!is_valid_wrong_k, "Paillier proof verification succeeded with wrong k");

        // Verification should fail with wrong N
        let wrong_n = &public_key.n + BigInt::one();
        let is_valid_wrong_n = proof.verify(&wrong_n, &k, &ecdsa_pk_point).unwrap();
        assert!(!is_valid_wrong_n, "Paillier proof verification succeeded with wrong N");

         // Verification should fail with wrong ECDSA key
         let ecdsa_sk2 = k256::SecretKey::random(&mut rng);
         let ecdsa_pk_k256_2 = ecdsa_sk2.public_key().to_projective();
         let ecdsa_pk_point_2 = ECPoint::<Secp256k1>::from_projective_unchecked(ecdsa_pk_k256_2);
         let is_valid_wrong_ecdsa = proof.verify(&public_key.n, &k, &ecdsa_pk_point_2).unwrap();
         assert!(!is_valid_wrong_ecdsa, "Paillier proof verification succeeded with wrong ECDSA key");
    }
} 