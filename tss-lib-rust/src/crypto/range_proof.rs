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
#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;

    #[test]
    fn test_range_proof_alice_new() {
        let pk = 1.to_bigint().unwrap();
        let c = 2.to_bigint().unwrap();
        let ntilde = 3.to_bigint().unwrap();
        let h1 = 4.to_bigint().unwrap();
        let h2 = 5.to_bigint().unwrap();
        let m = 6.to_bigint().unwrap();
        let r = 7.to_bigint().unwrap();
        let proof = RangeProofAlice::new(&pk, &c, &ntilde, &h1, &h2, &m, &r);
        assert!(proof.is_ok());
    }
}
