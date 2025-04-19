use ed25519_dalek::Ed25519;
pub fn get_curve_by_name(name: CurveName) -> Option<Box<dyn ToEncodedPoint<Secp256k1>>> {
