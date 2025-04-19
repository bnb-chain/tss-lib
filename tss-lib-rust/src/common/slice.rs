use num_bigint::BigInt;

pub fn bigints_to_bytes(bigints: &[BigInt]) -> Vec<Vec<u8>> {
    bigints.iter().map(|b| b.to_bytes_le().1).collect()
}

pub fn multi_bytes_to_bigints(bytes: &[Vec<u8>]) -> Vec<BigInt> {
    bytes.iter().map(|b| BigInt::from_bytes_le(num_bigint::Sign::Plus, b)).collect()
}

pub fn non_empty_bytes(bz: &[u8]) -> bool {
    !bz.is_empty()
}

pub fn non_empty_multi_bytes(bzs: &[Vec<u8>], expect_len: Option<usize>) -> bool {
    if let Some(len) = expect_len {
        if bzs.len() != len {
            return false;
        }
    }
    bzs.iter().all(|bz| non_empty_bytes(bz))
}

pub fn pad_to_length_bytes_in_place(src: &mut Vec<u8>, length: usize) {
    while src.len() < length {
        src.insert(0, 0);
    }
}
