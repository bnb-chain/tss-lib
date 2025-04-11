// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/common/int.go

use num_bigint_dig::{BigInt, Sign};
use num_traits::{Zero, One, Signed, Num};

/// Represents a modulus for modular arithmetic operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModInt {
    modulus: BigInt,
}

impl ModInt {
    /// Creates a new `ModInt` with the given modulus.
    pub fn new(modulus: BigInt) -> Self {
        // Ensure modulus is positive
        assert!(modulus.sign() == Sign::Plus, "Modulus must be positive");
        ModInt { modulus }
    }

    /// Returns the underlying modulus as a BigInt.
    pub fn modulus(&self) -> &BigInt {
        &self.modulus
    }

    /// Performs modular addition: (x + y) % mod.
    pub fn add(&self, x: &BigInt, y: &BigInt) -> BigInt {
        (x + y).modpow(&BigInt::one(), &self.modulus)
    }

    /// Performs modular subtraction: (x - y) % mod.
    pub fn sub(&self, x: &BigInt, y: &BigInt) -> BigInt {
        (x - y).modpow(&BigInt::one(), &self.modulus)
    }

    /// Performs modular multiplication: (x * y) % mod.
    pub fn mul(&self, x: &BigInt, y: &BigInt) -> BigInt {
        (x * y).modpow(&BigInt::one(), &self.modulus)
    }

    /// Performs modular exponentiation: (base ^ exponent) % mod.
    pub fn exp(&self, base: &BigInt, exponent: &BigInt) -> BigInt {
        base.modpow(exponent, &self.modulus)
    }

    /// Calculates the modular multiplicative inverse: (g ^ -1) % mod.
    /// Returns None if the inverse does not exist (i.e., gcd(g, mod) != 1).
    pub fn mod_inverse(&self, g: &BigInt) -> Option<BigInt> {
        // Ensure g is positive for standard mod_inverse, handle negative g if necessary
        let g_mod = g.modpow(&BigInt::one(), &self.modulus);
        g_mod.modinv(&self.modulus)
    }

    /// Performs modular division using modular inverse: (x * y^-1) % mod.
    /// Returns None if the inverse of y does not exist.
    /// Note: This implements standard modular division, unlike the Go version's Div which was (x / y) % m.
    pub fn div(&self, x: &BigInt, y: &BigInt) -> Option<BigInt> {
        self.mod_inverse(y).map(|y_inv| self.mul(x, &y_inv))
    }
}

/// Checks if a BigInt `b` is within the interval [0, bound).
/// Equivalent to 0 <= b < bound.
pub fn is_in_interval(b: &BigInt, bound: &BigInt) -> bool {
    !b.is_negative() && b < bound
}

/// Appends the byte representation of a BigInt to an existing byte slice.
/// The BigInt is appended in big-endian byte order.
pub fn append_bigint_to_bytes_slice(initial_bytes: &[u8], appended: &BigInt) -> Vec<u8> {
    let mut result_bytes = Vec::with_capacity(initial_bytes.len() + appended.to_bytes_be().1.len());
    result_bytes.extend_from_slice(initial_bytes);
    result_bytes.extend_from_slice(&appended.to_bytes_be().1);
    result_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint_dig::RandBigInt;
    use num_traits::FromPrimitive;

    #[test]
    fn test_mod_int_operations() {
        let modulus = BigInt::from_u64(100).unwrap();
        let modular = ModInt::new(modulus.clone());

        let x = BigInt::from_u64(50).unwrap();
        let y = BigInt::from_u64(75).unwrap();
        let z = BigInt::from_u64(4).unwrap();

        // Add: (50 + 75) % 100 = 125 % 100 = 25
        assert_eq!(modular.add(&x, &y), BigInt::from_u64(25).unwrap());

        // Sub: (50 - 75) % 100 = -25 % 100 = 75
        assert_eq!(modular.sub(&x, &y), BigInt::from_u64(75).unwrap());
         // Sub: (75 - 50) % 100 = 25 % 100 = 25
        assert_eq!(modular.sub(&y, &x), BigInt::from_u64(25).unwrap());

        // Mul: (50 * 75) % 100 = 3750 % 100 = 50
        assert_eq!(modular.mul(&x, &y), BigInt::from_u64(50).unwrap());

        // Exp: (75 ^ 4) % 100 = 31640625 % 100 = 25
        assert_eq!(modular.exp(&y, &z), BigInt::from_u64(25).unwrap());

        // ModInverse: 75^-1 mod 100 does not exist (gcd(75, 100) = 25)
        assert_eq!(modular.mod_inverse(&y), None);
        // ModInverse: 7^-1 mod 100 = 43 (since 7 * 43 = 301 = 3*100 + 1)
        let seven = BigInt::from_u64(7).unwrap();
        assert_eq!(modular.mod_inverse(&seven), Some(BigInt::from_u64(43).unwrap()));

        // Div: (50 / 7) mod 100 = (50 * 7^-1) mod 100 = (50 * 43) mod 100 = 2150 mod 100 = 50
        assert_eq!(modular.div(&x, &seven), Some(BigInt::from_u64(50).unwrap()));
         // Div: (50 / 75) mod 100 - inverse doesn't exist
        assert_eq!(modular.div(&x, &y), None);
    }

    #[test]
    fn test_is_in_interval() {
        let bound = BigInt::from_u64(100).unwrap();
        let zero = BigInt::zero();
        let fifty = BigInt::from_u64(50).unwrap();
        let ninety_nine = BigInt::from_u64(99).unwrap();
        let one_hundred = BigInt::from_u64(100).unwrap();
        let neg_one = BigInt::from_i64(-1).unwrap();

        assert!(is_in_interval(&zero, &bound));
        assert!(is_in_interval(&fifty, &bound));
        assert!(is_in_interval(&ninety_nine, &bound));
        assert!(!is_in_interval(&one_hundred, &bound));
        assert!(!is_in_interval(&neg_one, &bound)); // Test negative
    }

    #[test]
    fn test_append_bigint_to_bytes_slice() {
        let initial = vec![0x01, 0x02];
        let num = BigInt::parse_bytes(b"1234567890", 10).unwrap(); // Example BigInt
        let num_bytes = num.to_bytes_be().1;

        let expected_len = initial.len() + num_bytes.len();
        let mut expected = Vec::with_capacity(expected_len);
        expected.extend_from_slice(&initial);
        expected.extend_from_slice(&num_bytes);

        let result = append_bigint_to_bytes_slice(&initial, &num);
        assert_eq!(result, expected);

        // Test with empty initial bytes
        let empty_initial: Vec<u8> = Vec::new();
        let result_empty = append_bigint_to_bytes_slice(&empty_initial, &num);
        assert_eq!(result_empty, num_bytes);

         // Test with zero BigInt
        let zero_bigint = BigInt::zero();
        let zero_bytes = zero_bigint.to_bytes_be().1; // Typically empty or [0x00] depending on impl? num-bigint gives empty for 0.
        let expected_zero = vec![0x01, 0x02];
        expected_zero.extend_from_slice(&zero_bytes);
        let result_zero = append_bigint_to_bytes_slice(&initial, &zero_bigint);
         assert_eq!(result_zero, expected_zero); // Should just be initial bytes if zero is empty bytes
    }
} 