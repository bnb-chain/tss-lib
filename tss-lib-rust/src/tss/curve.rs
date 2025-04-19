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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_get_curve() {
        let curve_name = CurveName::Secp256k1;
        let curve = get_curve_by_name(curve_name.clone());
        assert!(curve.is_some());
        assert_eq!(get_curve_by_name(curve_name.clone()).is_some(), true);
    }

    #[test]
    fn test_same_curve() {
        let curve1 = get_curve_by_name(CurveName::Secp256k1).unwrap();
        let curve2 = get_curve_by_name(CurveName::Secp256k1).unwrap();
        assert!(same_curve(&*curve1, &*curve2));
    }
}
