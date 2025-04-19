use num_bigint::BigInt;
use num_traits::{One, Zero};

pub struct ModInt {
    modulus: BigInt,
}

impl ModInt {
    pub fn new(modulus: BigInt) -> Self {
        ModInt { modulus }
    }

    pub fn add(&self, x: &BigInt, y: &BigInt) -> BigInt {
        (x + y) % &self.modulus
    }

    pub fn sub(&self, x: &BigInt, y: &BigInt) -> BigInt {
        (x - y) % &self.modulus
    }

    pub fn mul(&self, x: &BigInt, y: &BigInt) -> BigInt {
        (x * y) % &self.modulus
    }

    pub fn exp(&self, x: &BigInt, y: &BigInt) -> BigInt {
        x.modpow(y, &self.modulus)
    }

    pub fn mod_inverse(&self, g: &BigInt) -> Option<BigInt> {
        g.mod_inverse(&self.modulus)
    }
}

pub fn is_in_interval(b: &BigInt, bound: &BigInt) -> bool {
    b < bound && b >= &BigInt::zero()
}
