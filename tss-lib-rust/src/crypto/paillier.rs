use num_bigint::BigInt;
use num_traits::One;
use std::fmt;

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
    pub fn encrypt(&self, m: &BigInt) -> Result<BigInt, String> {
        if m < &BigInt::zero() || m >= &self.n {
            return Err("Message is too large or < 0".to_string());
        }
        let x = BigInt::one(); // Placeholder for random value
        let n2 = &self.n * &self.n;
        let gm = m.modpow(&self.n, &n2);
        let xn = x.modpow(&self.n, &n2);
        Ok((gm * xn) % n2)
    }
}

impl PrivateKey {
    pub fn decrypt(&self, c: &BigInt) -> Result<BigInt, String> {
        let n2 = &self.public_key.n * &self.public_key.n;
        let lc = (c.modpow(&self.lambda_n, &n2) - 1) / &self.public_key.n;
        let lg = (self.public_key.n + 1).modpow(&self.lambda_n, &n2) - 1 / &self.public_key.n;
        let inv_lg = lg.mod_inverse(&self.public_key.n).ok_or("No modular inverse")?;
        Ok((lc * inv_lg) % &self.public_key.n)
    }
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
