use sha2::{Digest, Sha512_256};
use num_bigint::BigInt;
use num_traits::Zero;

const HASH_INPUT_DELIMITER: u8 = b'$';

pub fn sha512_256(inputs: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha512_256::new();
    let in_len = inputs.len() as u64;
    if in_len == 0 {
        return vec![];
    }
    let mut data = Vec::new();
    data.extend_from_slice(&in_len.to_le_bytes());
    for input in inputs {
        data.extend_from_slice(input);
        data.push(HASH_INPUT_DELIMITER);
        data.extend_from_slice(&(input.len() as u64).to_le_bytes());
    }
    hasher.update(&data);
    hasher.finalize().to_vec()
}

pub fn sha512_256i(inputs: &[&BigInt]) -> BigInt {
    let mut hasher = Sha512_256::new();
    let in_len = inputs.len() as u64;
    if in_len == 0 {
        return BigInt::zero();
    }
    let mut data = Vec::new();
    data.extend_from_slice(&in_len.to_le_bytes());
    for input in inputs {
        let bytes = input.to_bytes_le().1;
        data.extend_from_slice(&bytes);
        data.push(HASH_INPUT_DELIMITER);
        data.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    }
    hasher.update(&data);
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &hasher.finalize())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha512_256() {
        let input = vec![b"hello", b"world"];
        let hash = sha512_256(&input);
        assert_eq!(hash.len(), 32); // SHA-512/256 produces a 32-byte hash
    }

    #[test]
    fn test_sha512_256i() {
        let input = vec![BigInt::from(123), BigInt::from(456)];
        let hash = sha512_256i(&input.iter().collect::<Vec<_>>());
        assert!(!hash.is_zero());
    }
}
