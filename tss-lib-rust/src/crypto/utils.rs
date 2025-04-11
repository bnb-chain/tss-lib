// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/crypto/utils.go

use crate::common::random::get_random_generator_of_quadratic_residue;
use num_bigint_dig::BigInt;
use num_prime::{PrimalityTestConfig, nt_funcs};
use rand::{CryptoRng, RngCore};
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("GenerateNTildei: needs two primes, received empty or nil primes")]
    NilPrimes,
    #[error("GenerateNTildei: expected two probable primes")]
    NonPrimeInput,
    #[error("Failed to generate random quadratic residue generator: {0}")]
    GeneratorError(String), // Or more specific error type if available
}

/// Generates N-tilde, h1, and h2 for Paillier based on two safe primes (p, q).
/// N-tilde = p * q
/// h1, h2 are random generators of the quadratic residues mod N-tilde.
/// Requires p and q to be probable primes.
pub fn generate_n_tilde_i<R: CryptoRng + RngCore>(
    rng: &mut R,
    safe_primes: [&BigInt; 2],
) -> Result<(BigInt, BigInt, BigInt), CryptoError> {
    let p = safe_primes[0];
    let q = safe_primes[1];

    // Basic nil check implicitly handled by references, but check primality
    let prime_check_config = Some(PrimalityTestConfig::strict());
    if !nt_funcs::is_prime(p, prime_check_config).probably() ||
       !nt_funcs::is_prime(q, prime_check_config).probably() {
        return Err(CryptoError::NonPrimeInput);
    }

    let n_tilde = p * q;

    // Generate h1 and h2 as random generators of QR mod n_tilde
    let h1 = get_random_generator_of_quadratic_residue(rng, &n_tilde)
        .ok_or_else(|| CryptoError::GeneratorError("Failed to generate h1".to_string()))?;
    let h2 = get_random_generator_of_quadratic_residue(rng, &n_tilde)
        .ok_or_else(|| CryptoError::GeneratorError("Failed to generate h2".to_string()))?;

    Ok((n_tilde, h1, h2))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::safe_prime::get_random_safe_primes_concurrent;
    use rand::thread_rng;
    use std::sync::Arc;
    use tokio::runtime::Runtime;
    use tokio::sync::Mutex;

    #[test]
    fn test_generate_n_tilde_i() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut rng = thread_rng();
            let rng_arc = Arc::new(Mutex::new(rng));

            // 1. Generate two safe primes first
            // Use smaller bit size for faster testing
            let safe_primes_pair = get_random_safe_primes_concurrent(64, 2, 2, Arc::clone(&rng_arc))
                .await
                .expect("Failed to generate safe primes for testing");

            let p = safe_primes_pair[0].safe_prime(); // p = 2p'+1
            let q = safe_primes_pair[1].safe_prime(); // q = 2q'+1

            // 2. Generate N-tilde, h1, h2
            let result = generate_n_tilde_i(&mut *rng_arc.lock().await, [&p, &q]);

            assert!(result.is_ok());
            let (n_tilde, h1, h2) = result.unwrap();

            println!("p: {}", p);
            println!("q: {}", q);
            println!("N-tilde: {}", n_tilde);
            println!("h1: {}", h1);
            println!("h2: {}", h2);

            // Basic validation
            assert_eq!(&n_tilde, &(p * q));
            assert!(h1 > BigInt::zero() && h1 < n_tilde);
            assert!(h2 > BigInt::zero() && h2 < n_tilde);

            // Check h1, h2 are likely quadratic residues (Jacobi symbol == 1)
            // Note: This doesn't guarantee they are *generators*
            use jacobi::Symbol;
            assert_eq!(Symbol::new(&h1, &n_tilde), Symbol::One);
            assert_eq!(Symbol::new(&h2, &n_tilde), Symbol::One);
        });
    }

    #[test]
    fn test_generate_n_tilde_i_non_prime() {
        let mut rng = thread_rng();
        let prime = BigInt::from(7u64);
        let non_prime = BigInt::from(9u64);

        let result1 = generate_n_tilde_i(&mut rng, [&prime, &non_prime]);
        assert!(matches!(result1, Err(CryptoError::NonPrimeInput)));

        let result2 = generate_n_tilde_i(&mut rng, [&non_prime, &prime]);
        assert!(matches!(result2, Err(CryptoError::NonPrimeInput)));
    }
} 