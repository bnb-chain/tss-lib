// Copyright © Swingby

// Translation of tss-lib-go/crypto/ckd/child_key_derivation.go

use crate::{
    common::{hash_utils::*, int::ModInt},
    crypto::ecpoint::{ECPoint, PointError},
    tss::Curve,
};

use elliptic_curve::{
    group::GroupEncoding,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    Curve as EllipticCurveTrait, CurveArithmetic,
};
use hmac::{
    digest::{
        consts::U64,
        core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
        generic_array::typenum::U32,
        HashMarker,
    },
    Hmac,
};
use k256::elliptic_curve::scalar::ScalarPrimitive;
use num_bigint_dig::{BigInt, Sign};
use num_traits::Num;
use sha2::Sha512;
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CkdError {
    #[error("index must be non-hardened (must be < 0x80000000)")]
    InvalidIndexHardened,
    #[error("cannot derive key beyond max depth ({MAX_DEPTH})")]
    MaxDepthExceeded,
    #[error("invalid derived key (I_L is out of range or zero)")]
    InvalidDerivedKey,
    #[error("derived child key is invalid (identity or zero coordinate)")]
    InvalidChildKey,
    #[error("point operation failed: {0}")]
    PointError(String),
    #[error("base58 decoding error: {0}")]
    Base58Error(String),
    #[error("invalid extended key format or checksum")]
    InvalidExtendedKeyFormat,
    #[error("unsupported curve for string deserialization")]
    UnsupportedCurve,
    #[error("HMAC error: {0}")]
    HmacError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<PointError> for CkdError {
    fn from(err: PointError) -> Self {
        CkdError::PointError(err.to_string())
    }
}

/// Hardened key constant.
pub const HARDENED_KEY_START: u32 = 0x80000000; // 2^31
/// Maximum derivation depth.
pub const MAX_DEPTH: u8 = 255;
/// Compressed public key length (33 bytes).
pub const PUB_KEY_BYTES_LEN_COMPRESSED: usize = 33;
/// Serialized extended key length (prefix + data, excluding checksum).
pub const SERIALIZED_KEY_LEN: usize = 78;

/// Represents a BIP-32 Extended Public Key.
#[derive(Clone, PartialEq, Eq)] // Custom Debug needed due to ECPoint
pub struct ExtendedKey<C: Curve + CurveArithmetic> {
    pub point: ECPoint<C>,
    pub depth: u8,
    pub child_index: u32,
    pub chain_code: Vec<u8>, // 32 bytes
    pub parent_fp: Vec<u8>, // 4 bytes
    pub version: Vec<u8>, // 4 bytes
}

impl<C> fmt::Debug for ExtendedKey<C>
where
    C: Curve + CurveArithmetic,
    ECPoint<C>: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedKey")
            .field("point", &self.point)
            .field("depth", &self.depth)
            .field("child_index", &self.child_index)
            .field("chain_code", &hex::encode(&self.chain_code))
            .field("parent_fp", &hex::encode(&self.parent_fp))
            .field("version", &hex::encode(&self.version))
            .finish()
    }
}

impl<C> ExtendedKey<C>
where
    C: Curve + CurveArithmetic,
    ECPoint<C>: Clone + PartialEq + fmt::Debug + Serialize + for<'de> Deserialize<'de>,
{
    /// Derives a child extended public key using non-hardened derivation.
    /// Returns the intermediate scalar `I_L` (from the left 32 bytes of the HMAC output)
    /// and the derived `ExtendedKey`.
    pub fn derive_child_key(
        &self,
        index: u32,
    ) -> Result<(BigInt, ExtendedKey<C>), CkdError> {
        if index >= HARDENED_KEY_START {
            return Err(CkdError::InvalidIndexHardened);
        }
        if self.depth == MAX_DEPTH {
            return Err(CkdError::MaxDepthExceeded);
        }

        let curve_q = C::ORDER_BIGINT;

        // Data = compressed_parent_pubkey(33) || index(4)
        let parent_pk_bytes = self.point.to_bytes(); // Assumes compressed format
        if parent_pk_bytes.len() != PUB_KEY_BYTES_LEN_COMPRESSED {
            return Err(CkdError::InternalError("Parent public key is not compressed".to_string()));
        }

        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&parent_pk_bytes);
        data.extend_from_slice(&index.to_be_bytes());

        // I = HMAC-SHA512(Key = parent_chain_code, Data = data)
        let mut mac = Hmac::<Sha512>::new_from_slice(&self.chain_code)
            .map_err(|e| CkdError::HmacError(e.to_string()))?;
        mac.update(&data);
        let i_bytes = mac.finalize().into_bytes();
        let il_bytes = &i_bytes[..32];
        let ir_bytes = &i_bytes[32..]; // Child chain code

        // I_L (interpret left 32 bytes as scalar)
        let il_num = BigInt::from_bytes_be(Sign::Plus, il_bytes);

        // Check if I_L is valid ( >= N or 0)
        if il_num >= curve_q || il_num.is_zero() {
            return Err(CkdError::InvalidDerivedKey);
        }

        // Child PubKey = parent_pubkey + I_L * G
        let delta_g = ECPoint::<C>::scalar_base_mult(&il_num);
        if delta_g.is_identity() {
            return Err(CkdError::InvalidChildKey);
        }

        let child_point = self.point.add(&delta_g)?;
        if child_point.is_identity() {
             // This check might be redundant given delta_g != identity, unless parent was identity?
            return Err(CkdError::InvalidChildKey);
        }

        // Child Extended Key
        let child_ext_key = ExtendedKey {
            point: child_point,
            depth: self.depth + 1,
            child_index: index,
            chain_code: ir_bytes.to_vec(),
            parent_fp: self.fingerprint()?, // Calculate fingerprint of the parent
            version: self.version.clone(), // Inherit version
        };

        Ok((il_num, child_ext_key))
    }

    /// Derives a child key by following a hierarchy path of indices.
    pub fn derive_child_key_from_hierarchy(
        &self,
        indices_hierarchy: &[u32],
    ) -> Result<(BigInt, ExtendedKey<C>), CkdError> {
        let curve_q = C::ORDER_BIGINT;
        let mod_q = ModInt::new(curve_q);

        let mut current_k = self.clone();
        let mut total_il_num = BigInt::zero();

        for &index in indices_hierarchy {
            let (il_num, child_key) = current_k.derive_child_key(index)?;
            current_k = child_key;
            total_il_num = mod_q.add(&total_il_num, &il_num);
        }
        Ok((total_il_num, current_k))
    }

    /// Calculates the BIP-32 fingerprint (first 4 bytes of HASH160 of compressed public key).
    pub fn fingerprint(&self) -> Result<Vec<u8>, CkdError> {
        let compressed_pk = self.point.to_bytes();
        if compressed_pk.len() != PUB_KEY_BYTES_LEN_COMPRESSED {
             return Err(CkdError::InternalError("Public key is not compressed for fingerprint".to_string()));
        }
        Ok(hash160(&compressed_pk)[..4].to_vec())
    }

    /// Serializes the extended public key to the base58-encoded string format (BIP-32).
    pub fn to_string(&self) -> Result<String, CkdError> {
        // version(4) || depth(1) || parentFP(4) || childIndex(4) || chaincode(32) || key(33) || checksum(4)
        let mut child_index_bytes = [0u8; 4];
        child_index_bytes.copy_from_slice(&self.child_index.to_be_bytes());

        let pub_key_bytes = self.point.to_bytes();
        if pub_key_bytes.len() != PUB_KEY_BYTES_LEN_COMPRESSED {
            return Err(CkdError::InternalError("Public key is not compressed for serialization".to_string()));
        }

        let mut serialized_bytes = Vec::with_capacity(SERIALIZED_KEY_LEN);
        serialized_bytes.extend_from_slice(&self.version);
        serialized_bytes.push(self.depth);
        serialized_bytes.extend_from_slice(&self.parent_fp);
        serialized_bytes.extend_from_slice(&child_index_bytes);
        serialized_bytes.extend_from_slice(&self.chain_code);
        serialized_bytes.extend_from_slice(&pub_key_bytes);

        let checksum = double_sha256(&serialized_bytes)[..4].to_vec();

        let mut final_bytes = Vec::with_capacity(SERIALIZED_KEY_LEN + 4);
        final_bytes.extend_from_slice(&serialized_bytes);
        final_bytes.extend_from_slice(&checksum);

        Ok(bs58::encode(final_bytes).into_string())
    }

    /// Deserializes an extended public key from its base58-encoded string format.
    /// NOTE: This requires the Curve `C` to support `from_bytes` or similar functionality.
    /// The current `ECPoint` abstraction might need enhancement for this.
    pub fn from_string(key_str: &str) -> Result<Self, CkdError> {
        let decoded = bs58::decode(key_str)
            .into_vec()
            .map_err(|e| CkdError::Base58Error(e.to_string()))?;

        if decoded.len() != SERIALIZED_KEY_LEN + 4 {
            return Err(CkdError::InvalidExtendedKeyFormat);
        }

        // Split payload and checksum
        let payload = &decoded[..SERIALIZED_KEY_LEN];
        let checksum = &decoded[SERIALIZED_KEY_LEN..];

        // Verify checksum
        let expected_checksum = &double_sha256(payload)[..4];
        if checksum != expected_checksum {
            return Err(CkdError::InvalidExtendedKeyFormat);
        }

        // Deserialize fields
        let version = payload[0..4].to_vec();
        let depth = payload[4];
        let parent_fp = payload[5..9].to_vec();
        let child_index = u32::from_be_bytes(payload[9..13].try_into().unwrap());
        let chain_code = payload[13..45].to_vec();
        let key_data = &payload[45..78];

        // Deserialize the public key point
        let point = ECPoint::<C>::from_bytes(key_data)
            .map_err(|e| CkdError::PointError(format!("Failed to parse public key bytes: {}", e)))?;

        Ok(ExtendedKey {
            point,
            depth,
            child_index,
            chain_code,
            parent_fp,
            version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::Secp256k1;
    use num_bigint_dig::RandBigInt;
    use rand::thread_rng;
    use hex_literal::hex;

     // Helper to get curve order Q for K256
     fn get_k256_q() -> BigInt {
         let q_bytes = k256::Scalar::ORDER.to_be_bytes();
         BigInt::from_bytes_be(Sign::Plus, &q_bytes)
     }

    fn create_test_master_key() -> ExtendedKey<Secp256k1> {
         let mut rng = thread_rng();
         let q = get_k256_q();
         let sk = rng.gen_bigint_range(&BigInt::one(), &q);
         let pk_point = ECPoint::<Secp256k1>::scalar_base_mult(&sk);
         ExtendedKey {
             point: pk_point,
             depth: 0,
             child_index: 0,
             chain_code: vec![0u8; 32], // dummy chain code
             parent_fp: vec![0u8; 4],   // dummy parent fingerprint
             version: vec![0x04, 0x88, 0xB2, 0x1E], // mainnet xpub version
         }
     }

    #[test]
    fn test_derive_child_key() {
        let master_key = create_test_master_key();
        let index = 1u32; // Non-hardened index

        let derive_result = master_key.derive_child_key(index);
        assert!(derive_result.is_ok());
        let (il_num, child_key) = derive_result.unwrap();

        println!("Parent Key: {:?}", master_key);
        println!("Derived I_L: {}", il_num);
        println!("Child Key: {:?}", child_key);

        assert_eq!(child_key.depth, master_key.depth + 1);
        assert_eq!(child_key.child_index, index);
        assert_eq!(child_key.version, master_key.version);
        assert_ne!(child_key.chain_code, master_key.chain_code);
        assert_ne!(child_key.point, master_key.point);

        // Check parent fingerprint matches parent's actual fingerprint
        let parent_fp_actual = master_key.fingerprint().unwrap();
        assert_eq!(child_key.parent_fp, parent_fp_actual);
    }

    #[test]
    fn test_derive_child_key_from_hierarchy() {
         let master_key = create_test_master_key();
         let path = vec![0u32, 1u32, 2u32];

         let derive_result = master_key.derive_child_key_from_hierarchy(&path);
         assert!(derive_result.is_ok());
         let (total_il, final_child_key) = derive_result.unwrap();

         println!("Master Key: {:?}", master_key);
         println!("Hierarchy Path: {:?}", path);
         println!("Final Derived Key: {:?}", final_child_key);
         println!("Sum of I_L values (mod q): {}", total_il);

         assert_eq!(final_child_key.depth, master_key.depth + path.len() as u8);
         assert_eq!(final_child_key.child_index, path[path.len() - 1]);

         // Manual derivation for comparison
         let (il0, k0) = master_key.derive_child_key(path[0]).unwrap();
         let (il1, k1) = k0.derive_child_key(path[1]).unwrap();
         let (il2, k2) = k1.derive_child_key(path[2]).unwrap();

         assert_eq!(final_child_key, k2);

         let q = get_k256_q();
         let mod_q = ModInt::new(q);
         let expected_total_il = mod_q.add(&mod_q.add(&il0, &il1), &il2);
         assert_eq!(total_il, expected_total_il);
     }

    #[test]
    fn test_derive_errors() {
        let master_key = create_test_master_key();

        // Hardened index
        let hardened_index = HARDENED_KEY_START;
        assert!(matches!(master_key.derive_child_key(hardened_index), Err(CkdError::InvalidIndexHardened)));

        // Max depth
         let mut deep_key = master_key.clone();
         deep_key.depth = MAX_DEPTH;
         assert!(matches!(deep_key.derive_child_key(0), Err(CkdError::MaxDepthExceeded)));
    }

     #[test]
     fn test_fingerprint() {
         // Example from BIP-32 test vector 1 (master node)
         // Master key (m): seed = 000102...0f
         // Chain code: 873DFF81...54A7C5
         // Public key: 0339A360...842847
         let pk_bytes = hex!("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");
         let pk_point = ECPoint::<Secp256k1>::from_bytes(&pk_bytes).unwrap();
         let key = ExtendedKey {
             point: pk_point,
             depth: 0, child_index: 0, chain_code: vec![], parent_fp: vec![], version: vec![]
         };
         let fp = key.fingerprint().unwrap();
         // Expected fingerprint: 3442193e
         assert_eq!(fp, hex!("3442193e"));
     }

     #[test]
     fn test_serialization_deserialization() {
         // Test Vector 1: m
         let key_str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

         let key = ExtendedKey::<Secp256k1>::from_string(key_str).unwrap();

         assert_eq!(key.version, hex!("0488b21e"));
         assert_eq!(key.depth, 0);
         assert_eq!(key.parent_fp, hex!("00000000"));
         assert_eq!(key.child_index, 0);
         assert_eq!(key.chain_code, hex!("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"));
         let expected_pk_bytes = hex!("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");
         assert_eq!(key.point.to_bytes(), expected_pk_bytes);

         // Reserialize and check if matches original
         let reserialized_str = key.to_string().unwrap();
         assert_eq!(key_str, reserialized_str);

        // Test Vector 1: m/0
        let key_str_m0 = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA182cFMPfG3tKgmkaAkZNhUMWRmyPWAPrAsAGAmKj9MAr2oGh17vQyr1dqZV";
        let key_m0 = ExtendedKey::<Secp256k1>::from_string(key_str_m0).unwrap();
        assert_eq!(key_m0.depth, 1);
        assert_eq!(key_m0.parent_fp, hex!("3442193e")); // fingerprint of m
        assert_eq!(key_m0.child_index, 0);

         // Derive m/0 from m manually and check serialization
         let (_il, key_m0_derived) = key.derive_child_key(0).unwrap();
         assert_eq!(key_m0_derived.depth, key_m0.depth);
         assert_eq!(key_m0_derived.parent_fp, key_m0.parent_fp);
         assert_eq!(key_m0_derived.child_index, key_m0.child_index);
         assert_eq!(key_m0_derived.chain_code, key_m0.chain_code);
         assert_eq!(key_m0_derived.point, key_m0.point);
         assert_eq!(key_m0_derived.to_string().unwrap(), key_str_m0);

     }

    #[test]
    fn test_serialization_errors() {
        // Invalid base58
        assert!(matches!(ExtendedKey::<Secp256k1>::from_string("invalid-base58*"), Err(CkdError::Base58Error(_))));

        // Incorrect length
        let short_key = bs58::encode(vec![0u8; 70]).into_string();
        assert!(matches!(ExtendedKey::<Secp256k1>::from_string(&short_key), Err(CkdError::InvalidExtendedKeyFormat)));

        // Invalid checksum
         let key_str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
         let mut decoded = bs58::decode(key_str).into_vec().unwrap();
         let len = decoded.len();
         decoded[len - 1] ^= 0xff; // Flip last byte of checksum
         let bad_checksum_str = bs58::encode(decoded).into_string();
        assert!(matches!(ExtendedKey::<Secp256k1>::from_string(&bad_checksum_str), Err(CkdError::InvalidExtendedKeyFormat)));
    }
} 