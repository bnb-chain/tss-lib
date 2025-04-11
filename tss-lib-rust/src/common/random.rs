// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/common/random.go

use num_bigint_dig::{BigInt, RandBigInt, Sign};
use num_integer::Integer; // For GCD
use num_prime::nt_funcs; // For primality testing
use num_traits::{Zero, One, FromPrimitive};
use rand::{CryptoRng, RngCore};
use thiserror::Error;
use log::error;
use jacobi::Symbol; // For Jacobi symbol

// Re-export RandBigInt trait for convenience in other modules?
// pub use num_bigint_dig::RandBigInt;

const MUST_GET_RANDOM_INT_MAX_BITS: usize = 5000;

#[derive(Error, Debug)]
pub enum RandomError {
    #[error("Bits must be positive, non-zero, and less than {max_bits}, got {got_bits}")]
    BitsOutOfRange { max_bits: usize, got_bits: usize },
    #[error("Less-than value must be positive")]
    LessThanNotPositive,
    #[error("N must be positive")]
    NNotPositive,
    #[error("Error generating random number: {0}")]
    RandGenerationError(String),
    #[error("Invalid length requested: {0}")]
    InvalidLength(usize),
}

/// Generates a cryptographically secure random BigInt of `bits` length.
/// Panics if bits is <= 0 or >= max_bits, or if reading from rng fails.
pub fn must_get_random_int<R: CryptoRng + RngCore>(
    rng: &mut R,
    bits: usize,
) -> BigInt {
    if bits == 0 || bits > MUST_GET_RANDOM_INT_MAX_BITS {
        panic!(
            "MustGetRandomInt: bits should be positive, non-zero and less than {}",
            MUST_GET_RANDOM_INT_MAX_BITS
        );
    }
    // Generate a random BigInt uniformly in the range [0, 2^bits - 1]
    // RandBigInt::gen_biguint(bits) generates in [0, 2^bits - 1]
    rng.gen_bigint(bits)
    // // Alternative using gen_bigint_range:
    // let upper_bound = BigInt::one() << bits;
    // rng.gen_bigint_range(&BigInt::zero(), &upper_bound)
}

/// Generates a cryptographically secure random positive BigInt less than `less_than`.
/// Returns None if `less_than` is not positive.
pub fn get_random_positive_int<R: CryptoRng + RngCore>(
    rng: &mut R,
    less_than: &BigInt,
) -> Option<BigInt> {
    if less_than.sign() != Sign::Plus {
        error!("get_random_positive_int: less_than must be positive");
        return None;
    }
    // Generate a random BigInt uniformly in the range [0, less_than - 1]
    Some(rng.gen_bigint_range(&BigInt::zero(), less_than))
}

/// Generates a cryptographically secure random probable prime BigInt of `bits` length.
/// Returns None if `bits` <= 0.
pub fn get_random_prime_int<R: CryptoRng + RngCore>(
    rng: &mut R,
    bits: usize,
) -> Option<BigInt> {
    if bits == 0 {
        error!("get_random_prime_int: bits must be positive");
        return None;
    }
    // num_prime::gen_prime uses Miller-Rabin tests.
    Some(nt_funcs::gen_prime(rng, bits, None)) // None uses default MR rounds
}

/// Checks if `v` is in the multiplicative group modulo `n` (Z/nZ)*.
/// This means 0 < v < n and gcd(v, n) == 1.
pub fn is_number_in_multiplicative_group(n: &BigInt, v: &BigInt) -> bool {
    if n.sign() != Sign::Plus {
        return false; // n must be positive
    }
    v.sign() == Sign::Plus && v < n && v.gcd(n).is_one()
}

/// Generates a random element in the multiplicative group modulo `n` (Z/nZ)*.
/// Returns None if `n` is not positive.
pub fn get_random_positive_relatively_prime_int<R: CryptoRng + RngCore>(
    rng: &mut R,
    n: &BigInt,
) -> Option<BigInt> {
    if n.sign() != Sign::Plus {
        error!("get_random_positive_relatively_prime_int: n must be positive");
        return None;
    }
    loop {
        // Generate a random number in [1, n-1]
        let try_val = rng.gen_bigint_range(&BigInt::one(), n);
        if try_val.gcd(n).is_one() {
            return Some(try_val);
        }
    }
}

/// Generates a random generator of the group of quadratic residues modulo `n` (RQn).
/// Returns `f^2 mod n` where `f` is a random element from (Z/nZ)*.
/// Note: The Go comment states this only works if n is a product of two safe primes.
/// This property is not checked here but assumed if this function is called.
/// Returns None if `n` is not positive.
pub fn get_random_generator_of_quadratic_residue<R: CryptoRng + RngCore>(
    rng: &mut R,
    n: &BigInt,
) -> Option<BigInt> {
    if n.sign() != Sign::Plus {
        error!("get_random_generator_of_quadratic_residue: n must be positive");
        return None;
    }
    let f = get_random_positive_relatively_prime_int(rng, n)?;
    // Calculate f^2 mod n using modpow for efficiency and correctness with large numbers
    Some(f.modpow(&BigInt::from(2u8), n))
}

/// Generates a random quadratic non-residue modulo `n`.
/// It finds `w` such that Jacobi(w, n) == -1.
/// Assumes `n` is odd.
/// Returns None if `n` is not positive (or implicitly if `n` is even, as Jacobi is typically defined for odd n).
pub fn get_random_quadratic_non_residue<R: CryptoRng + RngCore>(
    rng: &mut R,
    n: &BigInt,
) -> Option<BigInt> {
     if n.sign() != Sign::Plus || n.is_even().unwrap_or(true) {
          error!("get_random_quadratic_non_residue: n must be positive and odd");
         return None;
     }
    loop {
        // Generate random w in [1, n-1]
        let w = rng.gen_bigint_range(&BigInt::one(), n);
        // Calculate Jacobi symbol using the `jacobi` crate
        match Symbol::new(&w, n) {
             Symbol::MinusOne => return Some(w),
             Symbol::One | Symbol::Zero => continue, // Try again if residue or gcd > 1
        }
    }
}

/// Generates a vector of random bytes of the specified length.
pub fn get_random_bytes<R: CryptoRng + RngCore>(
    rng: &mut R,
    length: usize,
) -> Result<Vec<u8>, RandomError> {
    if length == 0 {
        return Err(RandomError::InvalidLength(length));
    }
    let mut buf = vec![0u8; length];
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| RandomError::RandGenerationError(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use num_traits::Num;

    #[test]
    fn test_must_get_random_int() {
        let mut rng = thread_rng();
        let bits = 128;
        let val = must_get_random_int(&mut rng, bits);
        println!("Random {}-bit int: {}", bits, val);
        assert!(val.bits() <= bits as u64);
        assert!(val.sign() != Sign::Minus);

        let val2 = must_get_random_int(&mut rng, bits);
        assert_ne!(val, val2);
    }

    #[test]
    #[should_panic]
    fn test_must_get_random_int_panic_zero() {
        let mut rng = thread_rng();
        must_get_random_int(&mut rng, 0);
    }

    #[test]
    #[should_panic]
    fn test_must_get_random_int_panic_large() {
        let mut rng = thread_rng();
        must_get_random_int(&mut rng, MUST_GET_RANDOM_INT_MAX_BITS + 1);
    }

    #[test]
    fn test_get_random_positive_int() {
        let mut rng = thread_rng();
        let less_than = BigInt::from(10000u64);
        let val = get_random_positive_int(&mut rng, &less_than).unwrap();
        println!("Random int < {}: {}", less_than, val);
        assert!(val < less_than);
        assert!(val.sign() != Sign::Minus);

        let val2 = get_random_positive_int(&mut rng, &less_than).unwrap();
        assert_ne!(val, val2);

        // Test non-positive less_than
        let zero = BigInt::zero();
        let neg_one = BigInt::from(-1i64);
        assert!(get_random_positive_int(&mut rng, &zero).is_none());
        assert!(get_random_positive_int(&mut rng, &neg_one).is_none());
    }

    #[test]
    fn test_get_random_prime_int() {
        let mut rng = thread_rng();
        let bits = 64; // Smaller bits for faster test
        let prime = get_random_prime_int(&mut rng, bits).unwrap();
        println!("Random {}-bit prime: {}", bits, prime);
        assert!(prime.bits() <= bits as u64);
        assert!(nt_funcs::is_prime(&prime, None).probably());

        let prime2 = get_random_prime_int(&mut rng, bits).unwrap();
        assert_ne!(prime, prime2);

        // Test zero bits
        assert!(get_random_prime_int(&mut rng, 0).is_none());
    }

    #[test]
    fn test_is_number_in_multiplicative_group() {
        let n = BigInt::from(10u64);
        assert!(is_number_in_multiplicative_group(&n, &BigInt::from(1u64)));
        assert!(!is_number_in_multiplicative_group(&n, &BigInt::from(2u64))); // gcd=2
        assert!(is_number_in_multiplicative_group(&n, &BigInt::from(3u64)));
        assert!(!is_number_in_multiplicative_group(&n, &BigInt::from(4u64))); // gcd=2
        assert!(!is_number_in_multiplicative_group(&n, &BigInt::from(5u64))); // gcd=5
        assert!(!is_number_in_multiplicative_group(&n, &BigInt::from(6u64))); // gcd=2
        assert!(is_number_in_multiplicative_group(&n, &BigInt::from(7u64)));
        assert!(!is_number_in_multiplicative_group(&n, &BigInt::from(8u64))); // gcd=2
        assert!(is_number_in_multiplicative_group(&n, &BigInt::from(9u64)));
        assert!(!is_number_in_multiplicative_group(&n, &BigInt::from(10u64))); // v >= n
        assert!(!is_number_in_multiplicative_group(&n, &BigInt::from(0u64))); // v <= 0
        assert!(!is_number_in_multiplicative_group(&n, &BigInt::from(11u64))); // v >= n

        // Test non-positive n
        let zero = BigInt::zero();
        let neg_ten = BigInt::from(-10i64);
        assert!(!is_number_in_multiplicative_group(&zero, &BigInt::one()));
        assert!(!is_number_in_multiplicative_group(&neg_ten, &BigInt::one()));
    }

    #[test]
    fn test_get_random_positive_relatively_prime_int() {
        let mut rng = thread_rng();
        let n = BigInt::from(100u64);
        let val = get_random_positive_relatively_prime_int(&mut rng, &n).unwrap();
        println!("Random relative prime < {}: {}", n, val);
        assert!(val > BigInt::zero() && val < n);
        assert!(val.gcd(&n).is_one());

        let val2 = get_random_positive_relatively_prime_int(&mut rng, &n).unwrap();
        assert_ne!(val, val2);

         // Test non-positive n
        let zero = BigInt::zero();
        let neg_one = BigInt::from(-1i64);
        assert!(get_random_positive_relatively_prime_int(&mut rng, &zero).is_none());
        assert!(get_random_positive_relatively_prime_int(&mut rng, &neg_one).is_none());
    }

    #[test]
    fn test_get_random_generator_of_quadratic_residue() {
        let mut rng = thread_rng();
        // Use n = p*q where p, q are safe primes. p=7, q=11 => n=77
        let n = BigInt::from(77u64);
        let gen = get_random_generator_of_quadratic_residue(&mut rng, &n).unwrap();
        println!("Random QR generator mod {}: {}", n, gen);
        assert!(gen > BigInt::zero() && gen < n);
        // Check if it's actually a quadratic residue: Jacobi(gen, n) should be 1
        assert_eq!(Symbol::new(&gen, &n), Symbol::One);

         // Test non-positive n
        let zero = BigInt::zero();
        let neg_one = BigInt::from(-1i64);
        assert!(get_random_generator_of_quadratic_residue(&mut rng, &zero).is_none());
        assert!(get_random_generator_of_quadratic_residue(&mut rng, &neg_one).is_none());
    }

     #[test]
    fn test_get_random_quadratic_non_residue() {
        let mut rng = thread_rng();
        let n = BigInt::from(77u64); // Must be odd

        let qnr = get_random_quadratic_non_residue(&mut rng, &n).unwrap();
        println!("Random QNR mod {}: {}", n, qnr);
        assert!(qnr > BigInt::zero() && qnr < n);
        assert_eq!(Symbol::new(&qnr, &n), Symbol::MinusOne);

         // Test non-positive or even n
        let zero = BigInt::zero();
        let neg_one = BigInt::from(-1i64);
        let ten = BigInt::from(10u64);
        assert!(get_random_quadratic_non_residue(&mut rng, &zero).is_none());
        assert!(get_random_quadratic_non_residue(&mut rng, &neg_one).is_none());
        assert!(get_random_quadratic_non_residue(&mut rng, &ten).is_none()); // Even n
    }

    #[test]
    fn test_get_random_bytes() {
        let mut rng = thread_rng();
        let len = 32;
        let bytes = get_random_bytes(&mut rng, len).unwrap();
        println!("Random {} bytes: {:x?}", len, bytes);
        assert_eq!(bytes.len(), len);

        let bytes2 = get_random_bytes(&mut rng, len).unwrap();
        assert_ne!(bytes, bytes2);

        // Test zero length
        assert!(get_random_bytes(&mut rng, 0).is_err());
    }
} 