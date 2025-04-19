use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::Secp256k1;
use ed25519_dalek::Ed25519;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub enum CurveName {
    Secp256k1,
    Ed25519,
}

lazy_static! {
    static ref REGISTRY: Mutex<HashMap<CurveName, Box<dyn ToEncodedPoint>>> = {
        let mut m = HashMap::new();
        m.insert(CurveName::Secp256k1, Box::new(Secp256k1::default()));
        m.insert(CurveName::Ed25519, Box::new(Ed25519::default()));
        Mutex::new(m)
    };
}

pub fn register_curve(name: CurveName, curve: Box<dyn ToEncodedPoint>) {
    let mut registry = REGISTRY.lock().unwrap();
    registry.insert(name, curve);
}

pub fn get_curve_by_name(name: CurveName) -> Option<Box<dyn ToEncodedPoint>> {
    let registry = REGISTRY.lock().unwrap();
    registry.get(&name).cloned()
}

pub fn same_curve(lhs: &dyn ToEncodedPoint, rhs: &dyn ToEncodedPoint) -> bool {
    lhs.to_encoded_point(false) == rhs.to_encoded_point(false)
}
