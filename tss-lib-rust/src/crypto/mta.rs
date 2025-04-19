use num_bigint::BigInt;
use crate::common::hash::sha512_256i;

pub struct ProofBob {
    pub z: BigInt,
    pub zprm: BigInt,
    pub t: BigInt,
    pub v: BigInt,
    pub w: BigInt,
    pub s: BigInt,
    pub s1: BigInt,
    pub s2: BigInt,
    pub t1: BigInt,
    pub t2: BigInt,
}

impl ProofBob {
    pub fn new(session: &[u8], pk: &BigInt, ntilde: &BigInt, h1: &BigInt, h2: &BigInt, c1: &BigInt, c2: &BigInt, x: &BigInt, y: &BigInt, r: &BigInt) -> Result<Self, String> {
        let z = BigInt::one(); // Placeholder for computed value
        let zprm = BigInt::one(); // Placeholder for computed value
        let t = BigInt::one(); // Placeholder for computed value
        let v = BigInt::one(); // Placeholder for computed value
        let w = BigInt::one(); // Placeholder for computed value
        let s = BigInt::one(); // Placeholder for computed value
        let s1 = BigInt::one(); // Placeholder for computed value
        let s2 = BigInt::one(); // Placeholder for computed value
        let t1 = BigInt::one(); // Placeholder for computed value
        let t2 = BigInt::one(); // Placeholder for computed value

        Ok(ProofBob { z, zprm, t, v, w, s, s1, s2, t1, t2 })
    }
}
