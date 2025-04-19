use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;
use num_bigint::BigInt;
use std::fmt;

pub struct ECPoint {
    pub curve: k256::Secp256k1,
    pub x: BigInt,
    pub y: BigInt,
}

impl ECPoint {
    pub fn new(curve: k256::Secp256k1, x: BigInt, y: BigInt) -> Result<Self, String> {
        if !curve.is_on_curve(&x, &y) {
            return Err("Point is not on the curve".to_string());
        }
        Ok(ECPoint { curve, x, y })
    }

    pub fn add(&self, other: &ECPoint) -> Result<ECPoint, String> {
        let (x, y) = self.curve.add(&self.x, &self.y, &other.x, &other.y);
        ECPoint::new(self.curve, x, y)
    }

    pub fn scalar_mult(&self, k: &BigInt) -> Result<ECPoint, String> {
        let (x, y) = self.curve.scalar_mult(&self.x, &self.y, k);
        ECPoint::new(self.curve, x, y)
    }

    pub fn to_ecdsa_pub_key(&self) -> PublicKey {
        PublicKey::from_affine_coordinates(&self.x, &self.y, false)
    }
}

impl fmt::Display for ECPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ECPoint {{ x: {}, y: {} }}", self.x, self.y)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;

    #[test]
    fn test_ecpoint_add() {
        let curve = k256::Secp256k1::default();
        let point1 = ECPoint::new(curve, 1.to_bigint().unwrap(), 2.to_bigint().unwrap()).unwrap();
        let point2 = ECPoint::new(curve, 3.to_bigint().unwrap(), 4.to_bigint().unwrap()).unwrap();
        let result = point1.add(&point2);
        assert!(result.is_ok());
    }
}
