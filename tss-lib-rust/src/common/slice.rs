// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/common/slice.go

use num_bigint_dig::{BigInt, Sign};

/// Converts a slice of BigInt references to a Vec of Vec<u8> (big-endian bytes).
/// Assumes input references are valid.
pub fn bigints_to_bytes(big_ints: &[&BigInt]) -> Vec<Vec<u8>> {
    big_ints.iter()
        .map(|&n| n.to_bytes_be().1) // .1 extracts the Vec<u8>
        .collect()
}

/// Converts a slice of byte vectors into a Vec of BigInt.
/// Bytes are interpreted as big-endian unsigned integers.
pub fn multi_bytes_to_bigints(bytes: &[Vec<u8>]) -> Vec<BigInt> {
    bytes.iter()
        .map(|bz| BigInt::from_bytes_be(Sign::Plus, bz))
        .collect()
}

/// Returns true if the byte slice is non-empty.
pub fn non_empty_bytes(bz: &[u8]) -> bool {
    !bz.is_empty()
}

/// Returns true if the slice of byte slices is non-empty,
/// all inner slices are non-empty, and optionally if the outer slice
/// has the expected length.
pub fn non_empty_multi_bytes(bzs: &[Vec<u8>], expect_len: Option<usize>) -> bool {
    if bzs.is_empty() {
        return false;
    }
    if let Some(expected) = expect_len {
        if bzs.len() != expected {
            return false;
        }
    }
    // Check if all inner slices are non-empty
    bzs.iter().all(|bz| non_empty_bytes(bz))
}

/// Prepends zero bytes to `src` until it reaches `length`.
/// Returns a new Vec; does not modify the input slice `src`.
/// If `src` is already >= `length`, a copy of `src` is returned.
pub fn pad_to_length_bytes(src: &[u8], length: usize) -> Vec<u8> {
    let src_len = src.len();
    if src_len >= length {
        src.to_vec()
    } else {
        let padding_len = length - src_len;
        let mut result = Vec::with_capacity(length);
        result.resize(padding_len, 0u8); // Prepend zeros
        result.extend_from_slice(src);
        result
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint_dig::Num;

    #[test]
    fn test_bigints_to_bytes_conversion() {
        let num1 = BigInt::from(12345u64);
        let num2 = BigInt::from(0u64);
        let num3 = BigInt::parse_bytes(b"ABCDEF", 16).unwrap();

        let nums = vec![&num1, &num2, &num3];
        let bytes_vec = bigints_to_bytes(&nums);

        assert_eq!(bytes_vec.len(), 3);
        assert_eq!(BigInt::from_bytes_be(Sign::Plus, &bytes_vec[0]), num1);
        assert_eq!(BigInt::from_bytes_be(Sign::Plus, &bytes_vec[1]), num2); // 0 -> empty vec or single 0 byte?
         // num-bigint returns empty vec for 0. Let's verify.
         if bytes_vec[1].is_empty() {
             assert_eq!(BigInt::from(0u8), num2);
         } else {
             assert_eq!(BigInt::from_bytes_be(Sign::Plus, &bytes_vec[1]), num2);
         }
        assert_eq!(BigInt::from_bytes_be(Sign::Plus, &bytes_vec[2]), num3);

        let round_trip_nums = multi_bytes_to_bigints(&bytes_vec);
        assert_eq!(round_trip_nums.len(), 3);
        assert_eq!(round_trip_nums[0], num1);
        assert_eq!(round_trip_nums[1], num2);
        assert_eq!(round_trip_nums[2], num3);
    }

    #[test]
    fn test_multi_bytes_to_bigints_empty() {
        let bytes: Vec<Vec<u8>> = vec![];
        let ints = multi_bytes_to_bigints(&bytes);
        assert!(ints.is_empty());

         let bytes_inner_empty: Vec<Vec<u8>> = vec![vec![], vec![1, 2]];
         let ints_inner_empty = multi_bytes_to_bigints(&bytes_inner_empty);
         assert_eq!(ints_inner_empty[0], BigInt::zero());
         assert_eq!(ints_inner_empty[1], BigInt::from_bytes_be(Sign::Plus, &[1, 2]));
    }

    #[test]
    fn test_non_empty_bytes() {
        assert!(non_empty_bytes(&[1]));
        assert!(non_empty_bytes(&[0]));
        assert!(!non_empty_bytes(&[]));
    }

    #[test]
    fn test_non_empty_multi_bytes() {
        let bzs1 = vec![vec![1], vec![2, 3]];
        assert!(non_empty_multi_bytes(&bzs1, None));
        assert!(non_empty_multi_bytes(&bzs1, Some(2)));
        assert!(!non_empty_multi_bytes(&bzs1, Some(1)));

        let bzs2 = vec![vec![1], vec![]];
        assert!(!non_empty_multi_bytes(&bzs2, None));
        assert!(!non_empty_multi_bytes(&bzs2, Some(2)));

        let bzs3: Vec<Vec<u8>> = vec![];
        assert!(!non_empty_multi_bytes(&bzs3, None));
        assert!(!non_empty_multi_bytes(&bzs3, Some(0))); // Expect len 0 passes if vec empty

        let bzs4 = vec![vec![1]];
        assert!(non_empty_multi_bytes(&bzs4, Some(1)));
        assert!(!non_empty_multi_bytes(&bzs4, Some(2)));
    }

    #[test]
    fn test_pad_to_length_bytes() {
        let src1 = vec![1, 2, 3];
        let len1 = 5;
        let padded1 = pad_to_length_bytes(&src1, len1);
        assert_eq!(padded1, vec![0, 0, 1, 2, 3]);
        assert_eq!(padded1.len(), len1);

        let src2 = vec![1, 2, 3, 4, 5];
        let len2 = 5;
        let padded2 = pad_to_length_bytes(&src2, len2);
        assert_eq!(padded2, src2); // No padding needed
        assert_eq!(padded2.len(), len2);

        let src3 = vec![1, 2, 3, 4, 5, 6];
        let len3 = 5;
        let padded3 = pad_to_length_bytes(&src3, len3);
        assert_eq!(padded3, src3); // Src longer, returns copy
        assert_eq!(padded3.len(), src3.len());

        let src4 = vec![];
        let len4 = 3;
        let padded4 = pad_to_length_bytes(&src4, len4);
        assert_eq!(padded4, vec![0, 0, 0]);
        assert_eq!(padded4.len(), len4);

         let src5 = vec![1, 2];
         let len5 = 2;
         let padded5 = pad_to_length_bytes(&src5, len5);
         assert_eq!(padded5, src5);
         assert_eq!(padded5.len(), len5);
    }

} 