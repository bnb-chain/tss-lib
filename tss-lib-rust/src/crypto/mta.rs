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
#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;

    #[test]
    fn test_proof_bob_new() {
        let session = b"session";
        let pk = 1.to_bigint().unwrap();
        let ntilde = 2.to_bigint().unwrap();
        let h1 = 3.to_bigint().unwrap();
        let h2 = 4.to_bigint().unwrap();
        let c1 = 5.to_bigint().unwrap();
        let c2 = 6.to_bigint().unwrap();
        let x = 7.to_bigint().unwrap();
        let y = 8.to_bigint().unwrap();
        let r = 9.to_bigint().unwrap();
        let proof = ProofBob::new(session, &pk, &ntilde, &h1, &h2, &c1, &c2, &x, &y, &r);
        assert!(proof.is_ok());
    }
}
