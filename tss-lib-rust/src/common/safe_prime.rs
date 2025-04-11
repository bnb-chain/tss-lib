// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation & adaptation of tss-lib-go/common/safe_prime.go
// Original Go implementation based on: https://github.com/didiercrunch/paillier/blob/753322e473bf8ee20267c7824e68ae47360cc69b/safe_prime_generator.go
// Algorithm described in: "Safe Prime Generation with a Combined Sieve" https://eprint.iacr.org/2003/186.pdf

use num_bigint_dig::{BigInt, RandBigInt, Sign};
use num_integer::Integer; // For gcd
use num_prime::{nt_funcs, PrimalityTestConfig};
use num_traits::{One, Zero, FromPrimitive, ToPrimitive};
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, Semaphore};
use tokio::task;
use once_cell::sync::Lazy; // Use Lazy for static initialization


const PRIME_TEST_N: usize = 30; // Number of Miller-Rabin rounds

// Static values, lazily initialized
static TWO: Lazy<BigInt> = Lazy::new(|| BigInt::from_u64(2).unwrap());
static THREE: Lazy<BigInt> = Lazy::new(|| BigInt::from_u64(3).unwrap());

// Small primes for sieve (up to 53)
static SMALL_PRIMES: Lazy<Vec<u64>> = Lazy::new(|| {
    vec![3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
});

// Product of SMALL_PRIMES
static SMALL_PRIMES_PRODUCT: Lazy<BigInt> = Lazy::new(|| {
    SMALL_PRIMES.iter().fold(BigInt::one(), |acc, &p| acc * BigInt::from_u64(p).unwrap())
});

#[derive(Error, Debug)]
pub enum SafePrimeError {
    #[error("Safe prime size must be at least {min_bits} bits, got {got_bits}")]
    BitLengthTooSmall { min_bits: usize, got_bits: usize },
    #[error("Number of primes must be greater than 0, got {0}")]
    NumPrimesInvalid(usize),
    #[error("Generator work cancelled (timeout or explicit cancellation)")]
    GeneratorCancelled,
    #[error("Error during random number generation: {0}")]
    RandGenerationError(String),
    #[error("Internal error during prime generation: {0}")]
    InternalError(String),
    #[error("Concurrency limit reached")]
    ConcurrencyLimit,
     #[error("Tokio task join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

/// Represents a Sophie Germain safe prime pair (q, p) where p = 2q + 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GermainSafePrime {
    q: BigInt, // The Sophie Germain prime (also prime)
    p: BigInt, // The safe prime (p = 2q + 1)
}

impl GermainSafePrime {
    /// Returns the Sophie Germain prime `q`.
    pub fn prime(&self) -> &BigInt {
        &self.q
    }

    /// Returns the safe prime `p`.
    pub fn safe_prime(&self) -> &BigInt {
        &self.p
    }

    /// Validates if `q` and `p` are probably prime and if `p = 2q + 1`.
    pub fn validate(&self) -> bool {
        is_probably_prime(&self.q) &&
        let two = BigInt::from(2);
        let one = BigInt::from(1);
        let mut rng = thread_rng();

        let p_is_prime = is_prime(&self.p, PRIME_TEST_N, &mut rng).probably();
        let q_is_prime = is_prime(&self.q, PRIME_TEST_N, &mut rng).probably();
        let p_eq_2q_plus_1 = self.p == (&self.q * &two + &one);

        p_is_prime && q_is_prime && p_eq_2q_plus_1
    }
}

// Precomputed values for sieve
static SMALL_PRIMES: [u64; 15] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
];

// Lazily initialized product of small primes.
static SMALL_PRIMES_PRODUCT: Lazy<BigInt> = Lazy::new(|| {
    SMALL_PRIMES.iter().fold(BigInt::one(), |acc, &p| acc * BigInt::from(p))
});

/// Custom error types for safe prime generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafePrimeError {
    BitLenTooSmall,
    NumPrimesZero,
    GeneratorCancelled,
    GeneratorError(String),
}

impl fmt::Display for SafePrimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SafePrimeError::BitLenTooSmall => write!(f, "safe prime size must be at least 6 bits"),
            SafePrimeError::NumPrimesZero => write!(f, "num_primes must be greater than 0"),
            SafePrimeError::GeneratorCancelled => write!(f, "generator work cancelled"),
            SafePrimeError::GeneratorError(s) => write!(f, "generator error: {}", s),
        }
    }
}

impl std::error::Error for SafePrimeError {}

/// Calculates `2*q + 1`.
fn calculate_safe_prime_candidate(q: &BigInt) -> BigInt {
    q * BigInt::from(2u8) + BigInt::one()
}

/// Checks if a number is probably prime using Miller-Rabin.
fn probably_prime(n: &BigInt) -> bool {
    if n.sign() != Sign::Plus {
        return false;
    }
    // Use a default number of rounds if PRIME_TEST_N is None, otherwise use the constant.
    let config = PrimalityTestConfig::new(PRIME_TEST_N.unwrap_or(10));
    let mut rng = thread_rng();
    is_prime(n, Some(config), &mut rng).probably()
}

/// Checks if a number `n` is coprime to all `SMALL_PRIMES`.
fn is_coprime_to_small_primes(n: &BigInt) -> bool {
    let n_mod_product = n.mod_floor(&SMALL_PRIMES_PRODUCT);
    if n_mod_product.is_zero() {
        return false;
    }
    let n_mod_small = n_mod_product.to_u64().unwrap_or(0); // If it doesn't fit, it can't share factors
    if n_mod_small == 0 {
        return false;
    } // Check needed if n was larger than the product

    for &p in &SMALL_PRIMES {
        if n_mod_small % p == 0 {
            return false;
        }
    }
    true
}

/// Checks Pocklington's criterion for primality of `p = 2q + 1` where `q` is prime.
/// Specifically, checks if `a^(p-1) == 1 (mod p)` for a base `a` (typically 2).
fn is_pocklington_criterion_satisfied(p: &BigInt, a: &BigInt) -> bool {
    let one = BigInt::one();
    let p_minus_1 = p - &one;
    a.modpow(&p_minus_1, p).is_one()
}

/// Attempts to generate a single Sophie Germain safe prime pair of `p_bit_len` bits.
/// This is the core logic executed by each concurrent worker thread.
fn generate_safe_prime_single(p_bit_len: usize) -> Option<GermainSafePrime> {
    if p_bit_len < 6 {
        return None; // Consistent with Go version check
    }
    let q_bit_len = p_bit_len - 1;
    let mut rng = thread_rng();
    let two = BigInt::from(2u8);
    let three = BigInt::from(3u8);
    let one = BigInt::one();
    let zero = BigInt::zero();

    // Max attempts for the inner loops (finding a suitable q)
    const MAX_INCREMENT_TRIES: usize = 10 * 128; // Matches effective limit in Go impl

    loop {
        // 1. Generate initial random q candidate
        let mut q = rng.gen_prime(q_bit_len); // Start with a probable prime q

        for _ in 0..MAX_INCREMENT_TRIES {
            // Ensure q is odd (gen_prime should already do this, but check doesn't hurt)
            if q.is_even() {
                q += &one;
            }

            // 2. Preliminary primality test for q (coprime to small primes)
            if !is_coprime_to_small_primes(&q) {
                q += &two; // Increment q by 2 to maintain oddness
                continue;
            }

            // 3. Check q mod 3 != 1
            if q.mod_floor(&three) == one {
                q += &two;
                continue;
            }

            // Calculate p = 2q + 1
            let p = calculate_safe_prime_candidate(&q);

            // 4. Preliminary primality test for p (coprime to small primes)
            if !is_coprime_to_small_primes(&p) {
                q += &two;
                continue;
            }

            // 5. Final primality tests
            // Use robust test for q
            if !is_prime(&q, PRIME_TEST_N, &mut rng).probably() {
                 q += &two;
                 continue;
             }

            // Use Pocklington for p (with base 2)
            if is_pocklington_criterion_satisfied(&p, &two) {
                // Double check p's primality robustly just in case
                if is_prime(&p, PRIME_TEST_N, &mut rng).probably() {
                    return Some(GermainSafePrime { q, p });
                }
            }

            // If tests failed, increment q and try again
            q += &two;
        }
        // If MAX_INCREMENT_TRIES is reached without success, generate a new base q
    }
}

/// Concurrently generates the specified number of Sophie Germain safe prime pairs.
///
/// Args:
/// * `p_bit_len`: The desired bit length of the safe prime `p` (must be >= 6).
/// * `num_primes`: The number of safe prime pairs to generate (must be > 0).
/// * `concurrency`: The number of worker threads to spawn.
/// * `timeout`: Optional timeout duration for the generation process.
///
/// Returns:
/// A `Result` containing a `Vec` of `GermainSafePrime` pairs or a `SafePrimeError`.
pub fn get_random_safe_primes_concurrent(
    p_bit_len: usize,
    num_primes: usize,
    concurrency: usize,
    timeout: Option<Duration>,
) -> Result<Vec<GermainSafePrime>, SafePrimeError> {
    if p_bit_len < 6 {
        return Err(SafePrimeError::BitLenTooSmall);
    }
    if num_primes == 0 {
        return Err(SafePrimeError::NumPrimesZero);
    }
    if concurrency == 0 {
        return Err(SafePrimeError::GeneratorError("Concurrency must be > 0".to_string()));
    }

    let (prime_tx, prime_rx) = channel::<GermainSafePrime>();
    let (err_tx, err_rx) = channel::<String>(); // Channel for error messages from threads
    let results = Arc::new(Mutex::new(Vec::with_capacity(num_primes)));
    let needed = Arc::new(Mutex::new(num_primes));

    let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let prime_tx_clone = prime_tx.clone();
        let err_tx_clone = err_tx.clone();

        let handle = thread::spawn(move || {
            loop {
                // Basic check if work is already done by others - not perfect cancellation
                // but reduces redundant work if a thread starts late.
                // Proper cancellation requires checking an atomic flag frequently inside the loop.
                // TODO: Implement more fine-grained cancellation check inside generate_safe_prime_single if needed.

                match generate_safe_prime_single(p_bit_len) {
                    Some(pair) => {
                        if prime_tx_clone.send(pair).is_err() {
                            // Receiver likely dropped, means main thread exited or finished.
                            break;
                        }
                    }
                    None => {
                        // This case should theoretically not happen if p_bit_len >= 6
                        // but handle defensively.
                         if err_tx_clone.send("generate_safe_prime_single returned None unexpectedly".to_string()).is_err() {
                             break;
                         }
                    }
                }
                // Yield to allow other threads to run, prevent busy-looping on failure
                thread::yield_now();
            }
        });
        handles.push(handle);
    }

    // Drop the original sender so the receiver knows when all threads are done (or dropped)
    drop(prime_tx);
    drop(err_tx);

    let start_time = std::time::Instant::now();
    loop {
        // Check if we have enough results
        if *needed.lock().unwrap() == 0 {
            break;
        }

        // Check for timeout
        let current_timeout = if let Some(t) = timeout {
            t.checked_sub(start_time.elapsed()).unwrap_or_default()
        } else {
            Duration::from_secs(3600) // Default very long timeout if none specified
        };

        if current_timeout.is_zero() && timeout.is_some() {
             return Err(SafePrimeError::GeneratorCancelled); // Timeout reached
        }

        select! {
            // Prioritize receiving errors
            recv(err_rx) -> msg => match msg {
                Ok(err_msg) => return Err(SafePrimeError::GeneratorError(err_msg)),
                Err(_) => {}, // Channel closed, continue checking primes or timeout
            },
            // Then try receiving primes
            recv_timeout(prime_rx, current_timeout) -> result => match result {
                Ok(prime_pair) => {
                    let mut needed_guard = needed.lock().unwrap();
                    if *needed_guard > 0 {
                        results.lock().unwrap().push(prime_pair);
                        *needed_guard -= 1;
                    }
                    if *needed_guard == 0 {
                        break; // Got enough primes
                    }
                },
                Err(RecvTimeoutError::Timeout) => {
                    if timeout.is_some() {
                        return Err(SafePrimeError::GeneratorCancelled);
                    }
                    // If no timeout specified, continue looping
                },
                Err(RecvTimeoutError::Disconnected) => {
                    // All threads finished. Check if we have enough results.
                    if *needed.lock().unwrap() > 0 {
                        // Check if any error occurred before disconnect
                        if let Ok(err_msg) = err_rx.try_recv() {
                             return Err(SafePrimeError::GeneratorError(err_msg));
                        }
                        // Not enough primes generated and no explicit error, likely generation failed
                        return Err(SafePrimeError::GeneratorError("Prime generation threads finished without enough results".to_string()));
                    }
                    // Got enough primes just as threads finished
                    break;
                }
            }
        }
    }

    // Cleanup: Signal threads to stop (best effort) and wait for them.
    // This part is tricky without a dedicated cancellation mechanism like AtomicBool.
    // The threads will exit eventually when the prime_tx channel is fully dropped.
    // We don't explicitly join handles here to avoid blocking indefinitely if a thread hangs,
    // relying on the timeout mechanism for termination.

    Ok(Arc::try_unwrap(results).unwrap().into_inner().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;
    use std::time::Instant;

    #[test]
    fn test_validate_known_safe_prime() {
        // p = 23 = 2*11 + 1 (q=11)
        let q = 11.to_bigint().unwrap();
        let p = 23.to_bigint().unwrap();
        let sgp = GermainSafePrime { q, p };
        assert!(sgp.validate());
    }

    #[test]
    fn test_validate_known_non_safe_prime() {
        // p = 21 = 2*10 + 1 (q=10, not prime)
        let q = 10.to_bigint().unwrap();
        let p = 21.to_bigint().unwrap();
        let sgp = GermainSafePrime { q, p };
        assert!(!sgp.validate());

         // p = 17 = 2*8 + 1 (q=8, not prime)
         let q2 = 8.to_bigint().unwrap();
         let p2 = 17.to_bigint().unwrap(); // p is prime, q is not
         let sgp2 = GermainSafePrime { q: q2, p: p2 };
         assert!(!sgp2.validate());

         // p = 2*7+1 = 15 (p is not prime)
         let q3 = 7.to_bigint().unwrap(); // q is prime
         let p3 = 15.to_bigint().unwrap();
         let sgp3 = GermainSafePrime { q: q3, p: p3 };
         assert!(!sgp3.validate());
    }

    #[test]
    fn test_is_coprime_to_small_primes() {
        assert!(is_coprime_to_small_primes(&7.to_bigint().unwrap()));
        assert!(!is_coprime_to_small_primes(&15.to_bigint().unwrap())); // 3*5
        assert!(is_coprime_to_small_primes(&59.to_bigint().unwrap())); // Prime > 53
        assert!(!is_coprime_to_small_primes(&(SMALL_PRIMES_PRODUCT.clone() + BigInt::one()))); // Test large number
    }

    #[test]
    fn test_pocklington() {
        // p = 23 = 2*11+1, q=11 (prime)
        let p = 23.to_bigint().unwrap();
        let a = 2.to_bigint().unwrap();
        assert!(is_pocklington_criterion_satisfied(&p, &a));

        // p = 15 = 2*7+1, q=7 (prime), but p is not prime
        let p_comp = 15.to_bigint().unwrap();
        assert!(!is_pocklington_criterion_satisfied(&p_comp, &a)); // 2^14 mod 15 = 4 != 1
    }

    #[test]
    fn test_generate_single_safe_prime_small() {
        // Test with small bit size (>= 6)
        let pair = generate_safe_prime_single(10).expect("Failed to generate 10-bit safe prime");
        println!("Generated 10-bit safe prime pair: p={}, q={}", pair.p, pair.q);
        assert!(pair.validate());
        assert!(pair.p.bits() <= 10);
        assert!(pair.q.bits() <= 9);
    }

    // This test can be slow
    #[test]
    #[ignore] // Ignore by default due to potentially long runtime
    fn test_generate_single_safe_prime_medium() {
        let bit_len = 64;
        let start = Instant::now();
        let pair = generate_safe_prime_single(bit_len).expect("Failed to generate 64-bit safe prime");
        let duration = start.elapsed();
        println!(
            "Generated {}-bit safe prime pair: p={}, q={} (took {:?})",
            bit_len, pair.p, pair.q, duration
        );
        assert!(pair.validate());
        assert!(pair.p.bits() <= bit_len as u64);
        assert!(pair.q.bits() <= (bit_len - 1) as u64);
    }

    #[test]
    fn test_concurrent_generation_basic() {
        let bit_len = 10; // Small size for quick test
        let num_primes = 2;
        let concurrency = 2;
        let timeout = Some(Duration::from_secs(30));

        let result = get_random_safe_primes_concurrent(bit_len, num_primes, concurrency, timeout);
        assert!(result.is_ok());
        let primes = result.unwrap();
        assert_eq!(primes.len(), num_primes);
        for pair in primes {
             println!("Concurrent gen {}-bit: p={}, q={}", bit_len, pair.p, pair.q);
             assert!(pair.validate());
             assert!(pair.p.bits() <= bit_len as u64);
        }
    }

     #[test]
     fn test_concurrent_generation_more_primes_than_concurrency() {
         let bit_len = 8; // Smallest reasonable size
         let num_primes = 5;
         let concurrency = 2;
         let timeout = Some(Duration::from_secs(30));

         let result = get_random_safe_primes_concurrent(bit_len, num_primes, concurrency, timeout);
         assert!(result.is_ok(), "Expected Ok, got {:?}", result.err());
         let primes = result.unwrap();
         assert_eq!(primes.len(), num_primes);
         for pair in primes {
             println!("Concurrent gen {}-bit: p={}, q={}", bit_len, pair.p, pair.q);
             assert!(pair.validate());
             assert!(pair.p.bits() <= bit_len as u64);
         }
     }

    #[test]
    fn test_concurrent_generation_timeout() {
        let bit_len = 512; // Large size likely to timeout quickly
        let num_primes = 1;
        let concurrency = 1;
        let timeout = Some(Duration::from_millis(10)); // Very short timeout

        let result = get_random_safe_primes_concurrent(bit_len, num_primes, concurrency, timeout);
        assert!(matches!(result, Err(SafePrimeError::GeneratorCancelled)), "Expected Cancelled, got {:?}", result);
    }

    #[test]
    fn test_concurrent_generation_invalid_params() {
        assert!(matches!(get_random_safe_primes_concurrent(5, 1, 1, None), Err(SafePrimeError::BitLenTooSmall)));
        assert!(matches!(get_random_safe_primes_concurrent(10, 0, 1, None), Err(SafePrimeError::NumPrimesZero)));
         assert!(matches!(get_random_safe_primes_concurrent(10, 1, 0, None), Err(SafePrimeError::GeneratorError(_))));
    }
} 