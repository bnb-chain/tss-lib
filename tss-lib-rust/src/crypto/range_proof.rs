use num_bigint::BigInt;
use crate::common::hash::sha512_256i;

pub struct RangeProofAlice {
    pub z: BigInt,
    pub u: BigInt,
    pub w: BigInt,
    pub s: BigInt,
    pub s1: BigInt,
    pub s2: BigInt,
}

impl RangeProofAlice {
    pub fn new(pk: &BigInt, c: &BigInt, ntilde: &BigInt, h1: &BigInt, h2: &BigInt, m: &BigInt, r: &BigInt) -> Result<Self, String> {
        let z = BigInt::one(); // Placeholder for computed value
        let u = BigInt::one(); // Placeholder for computed value
        let w = BigInt::one(); // Placeholder for computed value
        let s = BigInt::one(); // Placeholder for computed value
        let s1 = BigInt::one(); // Placeholder for computed value
        let s2 = BigInt::one(); // Placeholder for computed value

        Ok(RangeProofAlice { z, u, w, s, s1, s2 })
    }
}
