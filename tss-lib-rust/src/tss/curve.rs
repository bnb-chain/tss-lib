use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;
use k256::Secp256k1;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub enum CurveName {
    Secp256k1,
}

lazy_static! {
    static ref REGISTRY: Mutex<HashMap<CurveName, Secp256k1>> = {
        let mut m = HashMap::new();
        m.insert(CurveName::Secp256k1, Secp256k1::default());
        Mutex::new(m)
    };
}

pub fn register_curve(name: CurveName, curve: Secp256k1) {
    let mut registry = REGISTRY.lock().unwrap();
    registry.insert(name, curve);
}

pub fn get_curve_by_name(name: CurveName) -> Option<Secp256k1> {
    let registry = REGISTRY.lock().unwrap();
    registry.get(&name).cloned()
}

pub fn get_curve_name(curve: &Secp256k1) -> Option<CurveName> {
    // Only one curve supported for now
    Some(CurveName::Secp256k1)
}

pub fn same_curve(lhs: &Secp256k1, rhs: &Secp256k1) -> bool {
    // Only one curve supported for now, always true
    true
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
        assert!(same_curve(&curve1, &curve2));
    }
}
