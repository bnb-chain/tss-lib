use num_bigint::BigInt;
use num_traits::One;

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
        self.q.is_probably_prime(30) && self.p == (&self.q * 2 + BigInt::one()) && self.p.is_probably_prime(30)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;

    #[test]
    fn test_germain_safe_prime_validate() {
        let q = 11.to_bigint().unwrap();
        let p = 23.to_bigint().unwrap(); // p = 2q + 1
        let gsp = GermainSafePrime::new(q, p);
        assert!(gsp.validate());
    }
}
