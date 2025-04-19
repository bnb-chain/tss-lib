pub fn new(curve: k256::Secp256k1, x: BigInt, y: BigInt) -> Result<Self, String> {
    if !curve.is_on_curve(&k256::AffinePoint::new(x, y).unwrap()) {
pub fn add(&self, other: &ECPoint) -> Result<ECPoint, String> {
    let point = k256::ProjectivePoint::from(self) + k256::ProjectivePoint::from(other);
    let (x, y) = point.to_affine().unwrap().into();
