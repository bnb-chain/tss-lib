use rand::Rng;
use num_bigint::{BigInt, RandBigInt};
use num_traits::{One, Zero};

const MUST_GET_RANDOM_INT_MAX_BITS: usize = 5000;

pub fn must_get_random_int<R: Rng>(rng: &mut R, bits: usize) -> BigInt {
    if bits <= 0 || bits > MUST_GET_RANDOM_INT_MAX_BITS {
        panic!("MustGetRandomInt: bits should be positive, non-zero and less than {}", MUST_GET_RANDOM_INT_MAX_BITS);
    }
    let max = BigInt::one() << bits;
    rng.gen_bigint_range(&BigInt::zero(), &max)
}

pub fn get_random_positive_int<R: Rng>(rng: &mut R, less_than: &BigInt) -> BigInt {
    if less_than <= &BigInt::zero() {
        return BigInt::zero();
    }
    loop {
        let candidate = must_get_random_int(rng, less_than.bits() as usize);
        if &candidate < less_than {
            return candidate;
        }
    }
}

pub fn get_random_prime_int<R: Rng>(rng: &mut R, bits: usize) -> BigInt {
    rng.gen_prime(bits)
}
