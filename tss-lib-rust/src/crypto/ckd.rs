use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::Secp256k1;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha512;
use num_bigint::BigInt;
use num_traits::Zero;
use std::fmt;

type HmacSha512 = Hmac<Sha512>;

pub struct ExtendedKey {
    pub public_key: k256::PublicKey,
    pub depth: u8,
    pub child_index: u32,
    pub chain_code: Vec<u8>,
    pub parent_fp: Vec<u8>,
    pub version: Vec<u8>,
}

impl ExtendedKey {
    pub fn new(public_key: k256::PublicKey, depth: u8, child_index: u32, chain_code: Vec<u8>, parent_fp: Vec<u8>, version: Vec<u8>) -> Self {
        ExtendedKey {
            public_key,
            depth,
            child_index,
            chain_code,
            parent_fp,
            version,
        }
    }

    pub fn derive_child_key(&self, index: u32) -> Result<ExtendedKey, Box<dyn std::error::Error>> {
        if index >= 0x80000000 {
            return Err("The index must be non-hardened".into());
        }
        if self.depth == 255 {
            return Err("Cannot derive key beyond max depth".into());
        }

        let mut mac = HmacSha512::new_from_slice(&self.chain_code)?;
        mac.update(&self.public_key.to_encoded_point(false).as_bytes());
        mac.update(&index.to_be_bytes());
        let result = mac.finalize().into_bytes();

        let il = BigInt::from_bytes_be(num_bigint::Sign::Plus, &result[..32]);
        let child_chain_code = result[32..].to_vec();

        let child_public_key = self.public_key.add(&Secp256k1::generator() * il)?;

        Ok(ExtendedKey {
            public_key: child_public_key,
            depth: self.depth + 1,
            child_index: index,
            chain_code: child_chain_code,
            parent_fp: self.parent_fp.clone(),
            version: self.version.clone(),
        })
    }
}

impl fmt::Display for ExtendedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtendedKey {{ depth: {}, child_index: {}, chain_code: {:?}, parent_fp: {:?}, version: {:?} }}", self.depth, self.child_index, self.chain_code, self.parent_fp, self.version)
    }
}
