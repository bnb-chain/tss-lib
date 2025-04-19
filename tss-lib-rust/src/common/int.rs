use num_bigint::BigInt;
use num_traits::Zero;

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
        g.modinv(&self.modulus).map(|inv| inv % &self.modulus)
    }
}

pub fn is_in_interval(b: &BigInt, bound: &BigInt) -> bool {
    b < bound && b >= &BigInt::zero()
}
#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;

    #[test]
    fn test_mod_int_add() {
        let modulus = 7.to_bigint().unwrap();
        let mi = ModInt::new(modulus);
        let x = 3.to_bigint().unwrap();
        let y = 5.to_bigint().unwrap();
        assert_eq!(mi.add(&x, &y), 1.to_bigint().unwrap());
    }

    #[test]
    fn test_is_in_interval() {
        let bound = 10.to_bigint().unwrap();
        let b = 5.to_bigint().unwrap();
        assert!(is_in_interval(&b, &bound));
    }
}
