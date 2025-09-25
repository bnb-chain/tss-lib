use num_bigint::BigInt;
use crate::common::hash::sha512_256i;

pub type HashCommitment = BigInt;
pub type HashDeCommitment = Vec<BigInt>;

pub struct HashCommitDecommit {
    pub c: HashCommitment,
    pub d: HashDeCommitment,
}

impl HashCommitDecommit {
    pub fn new_with_randomness(r: BigInt, secrets: &[BigInt]) -> Self {
        let mut parts = vec![r];
        parts.extend_from_slice(secrets);
        let hash = sha512_256i(&parts.iter().collect::<Vec<_>>());
        HashCommitDecommit { c: hash, d: parts }
    }

    pub fn verify(&self) -> bool {
        let hash = sha512_256i(&self.d.iter().collect::<Vec<_>>());
        hash == self.c
    }

    pub fn decommit(&self) -> Option<&[BigInt]> {
        if self.verify() {
            Some(&self.d[1..])
        } else {
            None
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;

    #[test]
    fn test_hash_commit_decommit() {
        let r = 1.to_bigint().unwrap();
        let secrets = vec![2.to_bigint().unwrap(), 3.to_bigint().unwrap()];
        let commit_decommit = HashCommitDecommit::new_with_randomness(r, &secrets);

        assert!(commit_decommit.verify());
        assert_eq!(commit_decommit.decommit(), Some(&secrets[..]));
    }
}
