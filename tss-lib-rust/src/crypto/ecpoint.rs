use k256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint, EncodedPoint};
use k256::{PublicKey as Secp256k1PublicKey, Secp256k1, Scalar as Secp256k1Scalar, ProjectivePoint};
use k256::elliptic_curve::{AffineXCoordinate, PrimeField};
use ed25519_dalek::{VerifyingKey as Ed25519PublicKey, SigningKey};
use num_bigint::BigInt;
use std::fmt;
use serde_derive::{Serialize, Deserialize};
use num_traits::Zero;
use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ECCurve {
    Secp256k1,
    Ed25519,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ECPoint {
    pub curve: ECCurve,
    pub x: BigInt,
    pub y: BigInt,
}

impl ECPoint {
    pub fn new(curve: ECCurve, x: BigInt, y: BigInt) -> Result<Self, String> {
        match curve {
            ECCurve::Secp256k1 => {
                let x_bytes = x.to_bytes_be().1;
                let y_bytes = y.to_bytes_be().1;
                let mut x_arr = [0u8; 32];
                let mut y_arr = [0u8; 32];
                if x_bytes.len() > 32 || y_bytes.len() > 32 {
                    return Err("Coordinate too large".to_string());
                }
                x_arr[32 - x_bytes.len()..].copy_from_slice(&x_bytes);
                y_arr[32 - y_bytes.len()..].copy_from_slice(&y_bytes);
                let encoded = EncodedPoint::<Secp256k1>::from_affine_coordinates(&x_arr.into(), &y_arr.into(), false);
                let affine = k256::elliptic_curve::AffinePoint::<Secp256k1>::from_encoded_point(&encoded);
                if affine.is_none().into() {
                    return Err("Point is not on the curve".to_string());
                }
                Ok(ECPoint { curve, x, y })
            }
            ECCurve::Ed25519 => {
                // Ed25519 public keys are 32 bytes, y is encoded, x is recovered
                let y_bytes = y.to_bytes_be().1;
                let mut y_arr = [0u8; 32];
                if y_bytes.len() > 32 {
                    return Err("Coordinate too large".to_string());
                }
                y_arr[32 - y_bytes.len()..].copy_from_slice(&y_bytes);
                // Try to construct a verifying key from y (Ed25519 uses compressed form)
                let pk = Ed25519PublicKey::from_bytes(&y_arr);
                if pk.is_err() {
                    return Err("Invalid Ed25519 public key encoding".to_string());
                }
                Ok(ECPoint { curve, x, y })
            }
        }
    }

    pub fn add(&self, other: &ECPoint) -> Result<ECPoint, String> {
        if self.curve != other.curve {
            return Err("Curve mismatch".to_string());
        }
        match self.curve {
            ECCurve::Secp256k1 => {
                let p1 = self.to_secp256k1_affine()?;
                let p2 = other.to_secp256k1_affine()?;
                let sum = ProjectivePoint::from(p1) + ProjectivePoint::from(p2);
                let sum_affine = sum.to_affine();
                let encoded = sum_affine.to_encoded_point(false);
                let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, encoded.x().unwrap());
                let y = BigInt::from_bytes_be(num_bigint::Sign::Plus, encoded.y().unwrap());
                ECPoint::new(ECCurve::Secp256k1, x, y)
            }
            ECCurve::Ed25519 => {
                Err("Ed25519 point addition not implemented".to_string())
            }
        }
    }

    pub fn scalar_mult(&self, k: &BigInt) -> Result<ECPoint, String> {
        match self.curve {
            ECCurve::Secp256k1 => {
                let p = self.to_secp256k1_affine()?;
                let k_bytes = k.to_bytes_be().1;
                let mut scalar_bytes = [0u8; 32];
                if k_bytes.len() > 32 {
                    return Err("Scalar too large".to_string());
                }
                scalar_bytes[32 - k_bytes.len()..].copy_from_slice(&k_bytes);
                let scalar_ct = Secp256k1Scalar::from_repr(scalar_bytes.into());
                if scalar_ct.is_some().into() {
                    let scalar = scalar_ct.unwrap();
                    let res = ProjectivePoint::from(p) * scalar;
                    let res_affine = res.to_affine();
                    let encoded = res_affine.to_encoded_point(false);
                    let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, encoded.x().unwrap());
                    let y = BigInt::from_bytes_be(num_bigint::Sign::Plus, encoded.y().unwrap());
                    ECPoint::new(ECCurve::Secp256k1, x, y)
                } else {
                    Err("Invalid scalar".to_string())
                }
            }
            ECCurve::Ed25519 => {
                Err("Ed25519 scalar multiplication not implemented".to_string())
            }
        }
    }

    pub fn is_on_curve(&self) -> bool {
        match self.curve {
            ECCurve::Secp256k1 => self.to_secp256k1_affine().is_ok(),
            ECCurve::Ed25519 => {
                let y_bytes = self.y.to_bytes_be().1;
                let mut y_arr = [0u8; 32];
                if y_bytes.len() > 32 {
                    return false;
                }
                y_arr[32 - y_bytes.len()..].copy_from_slice(&y_bytes);
                Ed25519PublicKey::from_bytes(&y_arr).is_ok()
            }
        }
    }

    pub fn to_secp256k1_affine(&self) -> Result<k256::elliptic_curve::AffinePoint<Secp256k1>, String> {
        if self.curve != ECCurve::Secp256k1 {
            return Err("Not a secp256k1 point".to_string());
        }
        let x_bytes = self.x.to_bytes_be().1;
        let y_bytes = self.y.to_bytes_be().1;
        let mut x_arr = [0u8; 32];
        let mut y_arr = [0u8; 32];
        if x_bytes.len() > 32 || y_bytes.len() > 32 {
            return Err("Coordinate too large".to_string());
        }
        x_arr[32 - x_bytes.len()..].copy_from_slice(&x_bytes);
        y_arr[32 - y_bytes.len()..].copy_from_slice(&y_bytes);
        let encoded = EncodedPoint::<Secp256k1>::from_affine_coordinates(&x_arr.into(), &y_arr.into(), false);
        let affine = k256::elliptic_curve::AffinePoint::<Secp256k1>::from_encoded_point(&encoded);
        if affine.is_some().into() {
            Ok(affine.unwrap())
        } else {
            Err("Invalid point encoding".to_string())
        }
    }
}

pub fn flatten_ecpoints(points: &[ECPoint]) -> Result<Vec<BigInt>, String> {
    let mut flat = Vec::with_capacity(points.len() * 2);
    for p in points {
        flat.push(p.x.clone());
        flat.push(p.y.clone());
    }
    Ok(flat)
}

pub fn unflatten_ecpoints(curve: ECCurve, flat: &[BigInt]) -> Result<Vec<ECPoint>, String> {
    if flat.len() % 2 != 0 {
        return Err("Input length must be even".to_string());
    }
    let mut points = Vec::with_capacity(flat.len() / 2);
    for i in (0..flat.len()).step_by(2) {
        points.push(ECPoint::new(curve.clone(), flat[i].clone(), flat[i + 1].clone())?);
    }
    Ok(points)
}

impl fmt::Display for ECPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ECPoint {{ curve: {:?}, x: {}, y: {} }}", self.curve, self.x, self.y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;
    use serde_json;
    use rand::rngs::OsRng;

    fn affine_to_bigints(affine: k256::elliptic_curve::AffinePoint<k256::Secp256k1>) -> (BigInt, BigInt) {
        let encoded = affine.to_encoded_point(false);
        let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, encoded.x().unwrap());
        let y = BigInt::from_bytes_be(num_bigint::Sign::Plus, encoded.y().unwrap());
        (x, y)
    }

    #[test]
    fn test_secp256k1_ecpoint_add() {
        let g = ProjectivePoint::GENERATOR;
        let affine = g.to_affine();
        let (x, y) = affine_to_bigints(affine);
        let p1 = ECPoint::new(ECCurve::Secp256k1, x.clone(), y.clone()).unwrap();
        let p2 = ECPoint::new(ECCurve::Secp256k1, x, y).unwrap();
        let sum = p1.add(&p2);
        assert!(sum.is_ok());
        let sum_point = sum.unwrap();
        assert!(sum_point.is_on_curve());
    }

    #[test]
    fn test_secp256k1_ecpoint_scalar_mult() {
        let g = ProjectivePoint::GENERATOR;
        let affine = g.to_affine();
        let (x, y) = affine_to_bigints(affine);
        let p = ECPoint::new(ECCurve::Secp256k1, x, y).unwrap();
        let k = 2.to_bigint().unwrap();
        let res = p.scalar_mult(&k);
        assert!(res.is_ok());
        let res_point = res.unwrap();
        assert!(res_point.is_on_curve());
    }

    #[test]
    fn test_ed25519_ecpoint_is_on_curve() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let mut csprng = OsRng {};
        let mut sk_bytes = [0u8; 32];
        csprng.fill_bytes(&mut sk_bytes);
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_key = signing_key.verifying_key();
        let pk_bytes = verifying_key.to_bytes();
        let y = BigInt::from_bytes_be(num_bigint::Sign::Plus, &pk_bytes);
        let x = BigInt::zero(); // Ed25519 x is not used for validation
        let p = ECPoint::new(ECCurve::Ed25519, x, y.clone()).unwrap();
        assert!(p.is_on_curve());
    }

    #[test]
    fn test_flatten_unflatten() {
        let g = ProjectivePoint::GENERATOR;
        let affine = g.to_affine();
        let (x, y) = affine_to_bigints(affine);
        let p = ECPoint::new(ECCurve::Secp256k1, x, y).unwrap();
        let points = vec![p.clone(), p.clone()];
        let flat = flatten_ecpoints(&points).unwrap();
        let unflat = unflatten_ecpoints(ECCurve::Secp256k1, &flat).unwrap();
        assert_eq!(points, unflat);
    }

    #[test]
    fn test_serde_json() {
        let g = ProjectivePoint::GENERATOR;
        let affine = g.to_affine();
        let (x, y) = affine_to_bigints(affine);
        let p = ECPoint::new(ECCurve::Secp256k1, x, y).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let p2: ECPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }
}
