use num_bigint::BigInt;
use crate::common::hash::sha512_256i;

pub struct ProofMod {
    pub w: BigInt,
    pub x: Vec<BigInt>,
    pub a: BigInt,
    pub b: BigInt,
    pub z: Vec<BigInt>,
}

impl ProofMod {
    pub fn new(session: &[u8], n: &BigInt, p: &BigInt, q: &BigInt) -> Result<Self, String> {
        let phi = (p - 1) * (q - 1);
        let w = BigInt::one(); // Placeholder for random value

        let y: Vec<BigInt> = vec![BigInt::one(); 80]; // Placeholder for random values

        let x: Vec<BigInt> = vec![BigInt::one(); 80]; // Placeholder for computed values
        let a = BigInt::one(); // Placeholder for computed value
        let b = BigInt::one(); // Placeholder for computed value
        let z: Vec<BigInt> = vec![BigInt::one(); 80]; // Placeholder for computed values

        Ok(ProofMod { w, x, a, b, z })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;

    #[test]
    fn test_proof_mod_new() {
        let session = b"session";
        let n = 1.to_bigint().unwrap();
        let p = 2.to_bigint().unwrap();
        let q = 3.to_bigint().unwrap();
        let proof = ProofMod::new(session, &n, &p, &q);
        assert!(proof.is_ok());
    }
}
