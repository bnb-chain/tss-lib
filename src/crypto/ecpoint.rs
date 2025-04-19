
pub fn new(curve: k256::Secp256k1, x: BigInt, y: BigInt) -> Result<ECPoint, String> {
    if !curve.is_on_curve(&x, &y) {
        return Err("Point is not on the curve".to_string());
    }
    Ok(ECPoint { curve, x, y })
}

pub fn add(&self, other: &ECPoint) -> Result<ECPoint, String> {
    let point = k256::ProjectivePoint::from(self) + k256::ProjectivePoint::from(other);
    let (x, y) = point.to_affine().unwrap().to_encoded_point(false).coordinates();
    Ok(ECPoint { curve: self.curve, x, y })
