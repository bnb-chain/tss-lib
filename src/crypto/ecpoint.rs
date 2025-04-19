use k256::elliptic_curve::sec1::ToEncodedPoint;

pub fn new(curve: k256::Secp256k1, x: BigInt, y: BigInt) -> Result<Self, String> {
    if !curve.contains_point(&k256::AffinePoint::from_coords(x, y).unwrap()) {
pub fn add(&self, other: &ECPoint) -> Result<ECPoint, String> {
    let point = k256::ProjectivePoint::from(self) + k256::ProjectivePoint::from(other);
    let (x, y) = point.to_affine().unwrap().to_encoded_point(false).coordinates();
