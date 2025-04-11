// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/common/hash_utils.go

use num_bigint_dig::BigInt;
use num_traits::One; // For modpow trick to ensure positive result

/// Implements rejection sampling by simply taking the hash modulo q.
///
/// Note: This is a direct translation of the Go code's `RejectionSample`.
/// However, simple modular reduction introduces bias if the hash space (2^256)
/// is not an exact multiple of q. A more cryptographically sound rejection
/// sampling would involve retrying if the hash value is >= q * floor(2^256 / q).
/// For this translation, we stick to the original logic.
pub fn rejection_sample(q: &BigInt, e_hash: &BigInt) -> BigInt {
    // Using modpow with exponent 1 ensures the result is positive in num-bigint-dig,
    // mimicking the behavior of Go's Mod which also returns a positive result.
    e_hash.modpow(&BigInt::one(), q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::FromPrimitive;

    #[test]
    fn test_rejection_sample() {
        let q = BigInt::from_u64(1000).unwrap();

        // Case 1: hash < q
        let hash1 = BigInt::from_u64(500).unwrap();
        let result1 = rejection_sample(&q, &hash1);
        assert_eq!(result1, hash1);

        // Case 2: hash == q
        let hash2 = BigInt::from_u64(1000).unwrap();
        let result2 = rejection_sample(&q, &hash2);
        assert_eq!(result2, BigInt::from_u64(0).unwrap()); // 1000 mod 1000 = 0

        // Case 3: hash > q
        let hash3 = BigInt::from_u64(1234).unwrap();
        let result3 = rejection_sample(&q, &hash3);
        assert_eq!(result3, BigInt::from_u64(234).unwrap()); // 1234 mod 1000 = 234

        // Case 4: hash is a large number (simulating typical hash output)
        let hash4 = BigInt::parse_bytes(b"abcdef1234567890abcdef1234567890", 16).unwrap();
        let result4 = rejection_sample(&q, &hash4);
        println!("Large hash mod q: {}", result4);
        assert!(result4 >= BigInt::zero() && result4 < q);

         // Case 5: Negative hash input (modpow handles this correctly)
         let hash5 = BigInt::from_signed_bytes_be(&BigInt::from_u64(1234).unwrap().to_signed_bytes_be()); // -1234 if interpreted as signed
         let hash5_neg = BigInt::from_signed_bytes_be(&[0x80 | 0x04, 0xD2]); // Example -1234
         let neg_hash = BigInt::from(-1234i64);
         let result5 = rejection_sample(&q, &neg_hash);
          // -1234 mod 1000 = -234 mod 1000 = 766
         assert_eq!(result5, BigInt::from(766u64));

    }
} 