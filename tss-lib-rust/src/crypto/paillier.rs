use num_bigint::{BigInt, RandBigInt, ToBigInt};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use std::fmt;
use num_primes::Generator;

pub struct PublicKey {
    pub n: BigInt,
}

pub struct PrivateKey {
    pub public_key: PublicKey,
    pub lambda_n: BigInt,
    pub phi_n: BigInt,
    pub p: BigInt,
    pub q: BigInt,
}

impl PublicKey {
    pub fn encrypt<R: rand::RngCore>(&self, rng: &mut R, m: &BigInt) -> Result<BigInt, String> {
        if m < &BigInt::zero() || m >= &self.n {
            return Err("Message is too large or < 0".to_string());
        }
        let n = &self.n;
        let n2 = n * n;
        // r must be in [1, n) and gcd(r, n) == 1
        let mut r;
        loop {
            r = rng.gen_bigint_range(&BigInt::one(), n);
            if num_integer::gcd(r.clone(), n.clone()) == BigInt::one() {
                break;
            }
        }
        let gm = (n + BigInt::one()).modpow(m, &n2);
        let rn = r.modpow(n, &n2);
        Ok((gm * rn) % &n2)
    }
}

impl PrivateKey {
    pub fn decrypt(&self, c: &BigInt) -> Result<BigInt, String> {
        let n2 = &self.public_key.n * &self.public_key.n;
        let lc = (c.modpow(&self.lambda_n, &n2) - 1) / &self.public_key.n;
        let lg = ((self.public_key.n.clone() + 1u32).modpow(&self.lambda_n, &n2) - 1u32.clone()) / &self.public_key.n;
        let inv_lg = lg.modinv(&self.public_key.n).ok_or("No modular inverse")?;
        Ok((lc * inv_lg) % &self.public_key.n)
    }
}

// Minimal key generation for testing (not constant-time, not for production)
pub fn generate_keypair(bits: usize) -> (PrivateKey, PublicKey) {
    let p_biguint = Generator::new_prime(bits / 2);
    let q_biguint = Generator::new_prime(bits / 2);
    let p = BigInt::from_bytes_be(num_bigint::Sign::Plus, &p_biguint.to_bytes_be());
    let q = BigInt::from_bytes_be(num_bigint::Sign::Plus, &q_biguint.to_bytes_be());
    let n = &p * &q;
    let lambda_n = num_integer::lcm(p.clone() - 1u32, q.clone() - 1u32);
    let phi_n = (&p - 1u32) * (&q - 1u32);
    let pk = PublicKey { n: n.clone() };
    let sk = PrivateKey {
        public_key: PublicKey { n },
        lambda_n,
        phi_n,
        p,
        q,
    };
    (sk, pk)
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey {{ n: {} }}", self.n)
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey {{ n: {}, lambda_n: {}, phi_n: {}, p: {}, q: {} }}", self.public_key.n, self.lambda_n, self.phi_n, self.p, self.q)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;

    #[test]
    fn test_public_key_encrypt() {
        // Use a small key for test speed (not secure!)
        let (_sk, pk) = generate_keypair(128);
        let m = 2.to_bigint().unwrap();
        let mut rng = rand::thread_rng();
        let result = pk.encrypt(&mut rng, &m);
        assert!(result.is_ok());
        let cipher = result.unwrap();
        assert_ne!(cipher, BigInt::zero());
    }
}
