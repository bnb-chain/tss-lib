// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/common/hash.go

use num_bigint_dig::BigInt;
use sha2::{Digest, Sha512_256};
use log::error; // Assuming a logger like `log` crate is set up elsewhere

const HASH_INPUT_DELIMITER: u8 = b'$';

fn prepare_hash_data(inputs: &[&[u8]]) -> Option<Vec<u8>> {
    if inputs.is_empty() {
        return None;
    }

    let input_len = inputs.len();
    let mut bz_size = 0;
    for bz in inputs {
        bz_size += bz.len();
    }

    // Capacity calculation:
    // 8 bytes for input_len prefix
    // bz_size for all input data
    // input_len for delimiters
    // input_len * 8 for length of each input
    let data_cap = 8 + bz_size + input_len + (input_len * 8);
    let mut data = Vec::with_capacity(data_cap);

    // Prefix with the number of inputs (u64 little-endian)
    data.extend_from_slice(&u64::try_from(input_len).unwrap_or(u64::MAX).to_le_bytes());

    for bz in inputs {
        data.extend_from_slice(bz);
        data.push(HASH_INPUT_DELIMITER);
        // Append length of the current input (u64 little-endian)
        data.extend_from_slice(&u64::try_from(bz.len()).unwrap_or(u64::MAX).to_le_bytes());
    }

    Some(data)
}


/// Computes SHA-512/256 hash of the input byte slices, with safety delimiters and length prefixes.
/// Protected against length extension attacks.
pub fn sha512_256(inputs: &[&[u8]]) -> Option<Vec<u8>> {
    let data = prepare_hash_data(inputs)?;

    let mut state = Sha512_256::new();
    state.update(&data);
    Some(state.finalize().to_vec())
}

/// Computes SHA-512/256 hash of the input BigInts, converting them to bytes.
/// Includes safety delimiters and length prefixes.
pub fn sha512_256i(inputs: &[&BigInt]) -> Option<BigInt> {
    if inputs.is_empty() {
        return None;
    }

    // Convert BigInts to byte slices (big-endian)
    let input_bytes: Vec<Vec<u8>> = inputs.iter().map(|n| n.to_bytes_be().1).collect();
    let input_slices: Vec<&[u8]> = input_bytes.iter().map(|v| v.as_slice()).collect();

    let data = prepare_hash_data(&input_slices)?;

    let mut state = Sha512_256::new();
    state.update(&data);
    let hash_bytes = state.finalize();
    Some(BigInt::from_bytes_be(num_bigint_dig::Sign::Plus, &hash_bytes))
}

/// Computes a tagged SHA-512/256 hash for BigInt inputs.
/// The tag is hashed first, then used to initialize the state.
pub fn sha512_256i_tagged(tag: &[u8], inputs: &[&BigInt]) -> Option<BigInt> {
    if inputs.is_empty() {
        // Decide if hashing just the tag is intended, or returning None.
        // Go version returned nil, so mirroring that.
        return None;
    }

    // Hash the tag first
    let tag_hash = Sha512_256::digest(tag);

    // Initialize the state with the tag hash twice (as in Go code)
    let mut state = Sha512_256::new();
    state.update(&tag_hash);
    state.update(&tag_hash);

    // Convert BigInts to byte slices (big-endian), handling potential nils implicitly by reference
    // (Rust references cannot be null, assuming valid BigInts are passed)
    let input_bytes: Vec<Vec<u8>> = inputs.iter().map(|n| n.to_bytes_be().1).collect();
    let input_slices: Vec<&[u8]> = input_bytes.iter().map(|v| v.as_slice()).collect();

    // Prepare the data part (excluding the tag)
    let data_part = prepare_hash_data(&input_slices)?;

    // Update the state with the prepared data
    state.update(&data_part);

    let final_hash_bytes = state.finalize();
    Some(BigInt::from_bytes_be(num_bigint_dig::Sign::Plus, &final_hash_bytes))
}

/// Computes SHA-512/256 hash of a single BigInt.
/// Note: This version lacks the length prefixes and delimiters used in the multi-input versions.
pub fn sha512_256i_one(input: &BigInt) -> BigInt {
    let data = input.to_bytes_be().1;
    let mut state = Sha512_256::new();
    state.update(&data);
    let hash_bytes = state.finalize();
    BigInt::from_bytes_be(num_bigint_dig::Sign::Plus, &hash_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint_dig::Num;

    #[test]
    fn test_sha512_256() {
        let data1 = b"hello";
        let data2 = b"world";

        let hash1 = sha512_256(&[&data1[..], &data2[..]]);
        assert!(hash1.is_some());
        println!("sha512_256(hello, world): {:x?}", hash1.as_ref().unwrap());

        let hash2 = sha512_256(&[&data1[..]]);
        assert!(hash2.is_some());
        println!("sha512_256(hello): {:x?}", hash2.as_ref().unwrap());

        let hash3 = sha512_256(&[&data2[..], &data1[..]]);
        assert!(hash3.is_some());
        println!("sha512_256(world, hello): {:x?}", hash3.as_ref().unwrap());

        // Ensure order matters and delimiter prevents simple concatenation collision
        assert_ne!(hash1, hash3);

        let combined = b"helloworld";
        let hash_combined = sha512_256(&[&combined[..]]);
        assert!(hash_combined.is_some());
        assert_ne!(hash1, hash_combined);

        // Test empty input
        assert!(sha512_256(&[]).is_none());

        // Test one empty slice
         let empty_slice = b"";
         let hash_empty1 = sha512_256(&[&empty_slice[..]]);
         assert!(hash_empty1.is_some());
         println!("sha512_256(""): {:x?}", hash_empty1.as_ref().unwrap());

         // Test empty slice with non-empty
         let hash_empty2 = sha512_256(&[&data1[..], &empty_slice[..]]);
         assert!(hash_empty2.is_some());
         println!("sha512_256(hello, ""): {:x?}", hash_empty2.as_ref().unwrap());
         assert_ne!(hash2, hash_empty2);
    }

    #[test]
    fn test_sha512_256i() {
        let num1 = BigInt::from_str_radix("12345678901234567890", 10).unwrap();
        let num2 = BigInt::from_str_radix("98765432109876543210", 10).unwrap();

        let hash1 = sha512_256i(&[&num1, &num2]);
        assert!(hash1.is_some());
        println!("sha512_256i(num1, num2): {}", hash1.as_ref().unwrap().to_str_radix(16));

        let hash2 = sha512_256i(&[&num1]);
        assert!(hash2.is_some());
        println!("sha512_256i(num1): {}", hash2.as_ref().unwrap().to_str_radix(16));

        let hash3 = sha512_256i(&[&num2, &num1]);
        assert!(hash3.is_some());
        println!("sha512_256i(num2, num1): {}", hash3.as_ref().unwrap().to_str_radix(16));

        assert_ne!(hash1, hash3);

        // Test concatenation equivalence prevention
        let num1_bytes = num1.to_bytes_be().1;
        let num2_bytes = num2.to_bytes_be().1;
        let mut combined_bytes = Vec::new();
        combined_bytes.extend(num1_bytes);
        combined_bytes.extend(num2_bytes);
        let combined_num = BigInt::from_bytes_be(num_bigint_dig::Sign::Plus, &combined_bytes);
        let hash_combined = sha512_256i_one(&combined_num); // Use simple hash for comparison
        assert_ne!(hash1.as_ref().unwrap(), &hash_combined);

        // Test empty input
        assert!(sha512_256i(&[]).is_none());
    }

    #[test]
    fn test_sha512_256i_tagged() {
        let tag = b"MY_UNIQUE_TAG";
        let num1 = BigInt::from(12345u64);
        let num2 = BigInt::from(67890u64);

        let hash1 = sha512_256i_tagged(tag, &[&num1, &num2]);
        assert!(hash1.is_some());
        println!("Tagged Hash 1: {}", hash1.as_ref().unwrap().to_str_radix(16));

        let hash2 = sha512_256i_tagged(tag, &[&num2, &num1]);
        assert!(hash2.is_some());
        println!("Tagged Hash 2: {}", hash2.as_ref().unwrap().to_str_radix(16));

        // Different order gives different hash
        assert_ne!(hash1, hash2);

        // Different tag gives different hash
        let tag2 = b"ANOTHER_TAG";
        let hash3 = sha512_256i_tagged(tag2, &[&num1, &num2]);
        assert!(hash3.is_some());
        println!("Tagged Hash 3 (different tag): {}", hash3.as_ref().unwrap().to_str_radix(16));
        assert_ne!(hash1, hash3);

        // Compare with non-tagged version
        let hash_untagged = sha512_256i(&[&num1, &num2]);
        assert!(hash_untagged.is_some());
        assert_ne!(hash1, hash_untagged);

         // Test empty input array
        assert!(sha512_256i_tagged(tag, &[]).is_none());
    }

    #[test]
    fn test_sha512_256i_one() {
        let num = BigInt::from(1234567890u64);
        let hash = sha512_256i_one(&num);
        println!("sha512_256i_one(num): {}", hash.to_str_radix(16));

        // Hash of the same number should be consistent
        let hash_again = sha512_256i_one(&num);
        assert_eq!(hash, hash_again);

        // Hash of different number should be different
        let num2 = BigInt::from(9876543210u64);
        let hash2 = sha512_256i_one(&num2);
        assert_ne!(hash, hash2);
    }

     // Helper to compare byte slices ignoring Option wrapping for brevity in asserts
    fn assert_hash_ne(h1: Option<Vec<u8>>, h2: Option<Vec<u8>>) {
        assert!(h1.is_some());
        assert!(h2.is_some());
        assert_ne!(h1.unwrap(), h2.unwrap());
    }
} 