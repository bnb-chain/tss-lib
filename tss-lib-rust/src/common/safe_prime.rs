use num_bigint::BigInt;
use num_traits::{One, Zero};

pub struct GermainSafePrime {
    q: BigInt,
    p: BigInt, // p = 2q + 1
}

impl GermainSafePrime {
    pub fn new(q: BigInt, p: BigInt) -> Self {
        GermainSafePrime { q, p }
    }

    pub fn prime(&self) -> &BigInt {
        &self.q
    }

    pub fn safe_prime(&self) -> &BigInt {
        &self.p
    }

    pub fn validate(&self) -> bool {
        self.q.is_probably_prime(30) && self.p == &(&self.q * 2 + BigInt::one()) && self.p.is_probably_prime(30)
    }
}
