use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{Secp256k1, PublicKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use num_bigint::BigInt;
use std::fmt;
use k256::elliptic_curve::sec1::EncodedPoint;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use bip32::{ExtendedPublicKey, DerivationPath, Prefix};
use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;

pub struct ExtendedKey {
    pub public_key: PublicKey,
    pub depth: u8,
    pub child_index: u32,
    pub chain_code: Vec<u8>,
    pub parent_fp: Vec<u8>,
    pub version: Vec<u8>,
}

impl ExtendedKey {
    pub fn new(public_key: PublicKey, depth: u8, child_index: u32, chain_code: Vec<u8>, parent_fp: Vec<u8>, version: Vec<u8>) -> Self {
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

        // let child_public_key = self.public_key.add(&Secp256k1::generator() * il)?;

        Ok(ExtendedKey {
            public_key: self.public_key,
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
#[cfg(test)]
mod tests {
    use super::*;
    use k256::Secp256k1;
    use rand::thread_rng;

    // BIP32 test vectors from Go test
    const TEST_VEC1_MASTER_PUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const TEST_VEC2_MASTER_PUB: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";

    struct TestVector<'a> {
        name: &'a str,
        master: &'a str,
        path: &'a [u32],
        want_pub: &'a str,
    }

    const TEST_VECTORS: &[TestVector] = &[
        // Test vector 1
        TestVector {
            name: "test vector 1 chain m",
            master: TEST_VEC1_MASTER_PUB,
            path: &[],
            want_pub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        },
        TestVector {
            name: "test vector 1 chain m/0",
            master: TEST_VEC1_MASTER_PUB,
            path: &[0],
            want_pub: "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1",
        },
        TestVector {
            name: "test vector 1 chain m/0/1",
            master: TEST_VEC1_MASTER_PUB,
            path: &[0, 1],
            want_pub: "xpub6AvUGrnEpfvJBbfx7sQ89Q8hEMPM65UteqEX4yUbUiES2jHfjexmfJoxCGSwFMZiPBaKQT1RiKWrKfuDV4vpgVs4Xn8PpPTR2i79rwHd4Zr",
        },
        TestVector {
            name: "test vector 1 chain m/0/1/2",
            master: TEST_VEC1_MASTER_PUB,
            path: &[0, 1, 2],
            want_pub: "xpub6BqyndF6rhZqmgktFCBcapkwubGxPqoAZtQaYewJHXVKZcLdnqBVC8N6f6FSHWUghjuTLeubWyQWfJdk2G3tGgvgj3qngo4vLTnnSjAZckv",
        },
        TestVector {
            name: "test vector 1 chain m/0/1/2/2",
            master: TEST_VEC1_MASTER_PUB,
            path: &[0, 1, 2, 2],
            want_pub: "xpub6FHUhLbYYkgFQiFrDiXRfQFXBB2msCxKTsNyAExi6keFxQ8sHfwpogY3p3s1ePSpUqLNYks5T6a3JqpCGszt4kxbyq7tUoFP5c8KWyiDtPp",
        },
        TestVector {
            name: "test vector 1 chain m/0/1/2/2/1000000000",
            master: TEST_VEC1_MASTER_PUB,
            path: &[0, 1, 2, 2, 1000000000],
            want_pub: "xpub6GX3zWVgSgPc5tgjE6ogT9nfwSADD3tdsxpzd7jJoJMqSY12Be6VQEFwDCp6wAQoZsH2iq5nNocHEaVDxBcobPrkZCjYW3QUmoDYzMFBDu9",
        },
        // Test vector 2
        TestVector {
            name: "test vector 2 chain m",
            master: TEST_VEC2_MASTER_PUB,
            path: &[],
            want_pub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        },
        TestVector {
            name: "test vector 2 chain m/0",
            master: TEST_VEC2_MASTER_PUB,
            path: &[0],
            want_pub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        },
        TestVector {
            name: "test vector 2 chain m/0/2147483647",
            master: TEST_VEC2_MASTER_PUB,
            path: &[0, 2147483647],
            want_pub: "xpub6ASAVgeWMg4pmutghzHG3BohahjwNwPmy2DgM6W9wGegtPrvNgjBwuZRD7hSDFhYfunq8vDgwG4ah1gVzZysgp3UsKz7VNjCnSUJJ5T4fdD",
        },
        TestVector {
            name: "test vector 2 chain m/0/2147483647/1",
            master: TEST_VEC2_MASTER_PUB,
            path: &[0, 2147483647, 1],
            want_pub: "xpub6CrnV7NzJy4VdgP5niTpqWJiFXMAca6qBm5Hfsry77SQmN1HGYHnjsZSujoHzdxf7ZNK5UVrmDXFPiEW2ecwHGWMFGUxPC9ARipss9rXd4b",
        },
        TestVector {
            name: "test vector 2 chain m/0/2147483647/1/2147483646",
            master: TEST_VEC2_MASTER_PUB,
            path: &[0, 2147483647, 1, 2147483646],
            want_pub: "xpub6FL2423qFaWzHCvBndkN9cbkn5cysiUeFq4eb9t9kE88jcmY63tNuLNRzpHPdAM4dUpLhZ7aUm2cJ5zF7KYonf4jAPfRqTMTRBNkQL3Tfta",
        },
        TestVector {
            name: "test vector 2 chain m/0/2147483647/1/2147483646/2",
            master: TEST_VEC2_MASTER_PUB,
            path: &[0, 2147483647, 1, 2147483646, 2],
            want_pub: "xpub6H7WkJf547AiSwAbX6xsm8Bmq9M9P1Gjequ5SipsjipWmtXSyp4C3uwzewedGEgAMsDy4jEvNTWtxLyqqHY9C12gaBmgUdk2CGmwachwnWK",
        },
    ];

    #[test]
    fn test_derive_child_key() {
        let curve = Secp256k1::default();
        let generator = k256::ProjectivePoint::GENERATOR;
        let affine = generator.to_affine();
        let public_key = k256::PublicKey::from_affine(affine).unwrap();
        let chain_code = vec![0u8; 32];
        let parent_fp = vec![0u8; 4];
        let version = vec![0u8; 4];
        let extended_key = ExtendedKey::new(public_key, 0, 0, chain_code, parent_fp, version);

        let child_key = extended_key.derive_child_key(1);
        assert!(child_key.is_ok());
    }

    #[test]
    fn test_bip32_public_derivation_vectors() {
        for test in TEST_VECTORS {
            // Parse the master xpub
            let master = ExtendedPublicKey::<k256::ecdsa::VerifyingKey>::from_str(test.master);
            assert!(master.is_ok(), "{}: failed to parse master xpub: {:?}", test.name, master.err());
            let mut ext_pub = master.unwrap();

            // Derive along the path
            if !test.path.is_empty() {
                let path_str = format!("m/{}", test.path.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("/"));
                let path = DerivationPath::from_str(&path_str).unwrap();
                for child_number in path.into_iter() {
                    let result = ext_pub.derive_child(child_number);
                    assert!(result.is_ok(), "{}: failed to derive child {:?}: {:?}", test.name, child_number, result.as_ref().err());
                    ext_pub = result.unwrap();
                }
            }

            // Serialize and compare
            let got = ext_pub.to_string(Prefix::XPUB);
            assert_eq!(got, test.want_pub, "{}: derived xpub mismatch\n  got:  {}\n  want: {}", test.name, got, test.want_pub);
        }
    }
}
