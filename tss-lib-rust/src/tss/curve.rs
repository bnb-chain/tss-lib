// Copyright © 2024tss-lib
//
// This file is part of tss-lib. The full tss-lib copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

use std::collections::HashMap;
use std::sync::OnceLock;
use k256::{Secp256k1, ProjectivePoint as Secp256k1Point};
use k256::elliptic_curve::Curve;
use num_bigint::BigInt;
// Ed25519/Curve25519 imports from curve25519-dalek
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar as Ed25519Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurveName {
    Secp256k1,
    Ed25519,
}

#[derive(Debug, Clone)]
pub enum CurveParams {
    Secp256k1 {
        order: BigInt,
        generator_projective: Secp256k1Point,
    },
    Ed25519 {
        order: BigInt,
        generator: EdwardsPoint,
    },
}

impl CurveParams {
    pub fn order(&self) -> &BigInt {
        match self {
            CurveParams::Secp256k1 { order, .. } => order,
            CurveParams::Ed25519 { order, .. } => order,
        }
    }
}

// Static map to store curve parameters once initialized
static CURVE_REGISTRY: OnceLock<HashMap<CurveName, CurveParams>> = OnceLock::new();

// Ed25519 order as per RFC 8032: l = 2^252 + 27742317777372353535851937790883648493
// Little-endian byte order
const ED25519_ORDER_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0
];

fn get_or_init_registry() -> &'static HashMap<CurveName, CurveParams> {
    CURVE_REGISTRY.get_or_init(|| {
        let mut map = HashMap::new();

        // --- Secp256k1 Parameters ---
        let secp256k1_order_bytes = Secp256k1::ORDER.to_be_bytes();
        let secp256k1_order = BigInt::from_bytes_be(num_bigint::Sign::Plus, &secp256k1_order_bytes);
        let secp256k1_generator = Secp256k1Point::GENERATOR;

        map.insert(CurveName::Secp256k1, CurveParams::Secp256k1 {
            order: secp256k1_order,
            generator_projective: secp256k1_generator,
        });

        // --- Ed25519 Parameters ---
        let ed25519_order = BigInt::from_bytes_le(num_bigint::Sign::Plus, &ED25519_ORDER_BYTES);
        let ed25519_generator = ED25519_BASEPOINT_POINT;

        map.insert(CurveName::Ed25519, CurveParams::Ed25519 {
            order: ed25519_order,
            generator: ed25519_generator,
        });

        map
    })
}

pub fn get_curve_params(name: CurveName) -> Option<&'static CurveParams> {
    get_or_init_registry().get(&name)
}

pub fn is_curve_supported(name: CurveName) -> bool {
    get_or_init_registry().contains_key(&name)
}

pub fn same_curve(lhs_name: CurveName, rhs_name: CurveName) -> bool {
    lhs_name == rhs_name
}

pub fn s256k1_params() -> CurveParams {
    get_curve_params(CurveName::Secp256k1).expect("Secp256k1 params not found in registry").clone()
}

pub fn ed25519_params() -> CurveParams {
    get_curve_params(CurveName::Ed25519).expect("Ed25519 params not found in registry").clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;
    use k256::elliptic_curve::group::Group;

    #[test]
    fn test_is_curve_supported() {
        assert!(is_curve_supported(CurveName::Secp256k1));
        assert!(is_curve_supported(CurveName::Ed25519));
    }

    #[test]
    fn test_get_curve_params() {
        let params_s256 = get_curve_params(CurveName::Secp256k1);
        assert!(params_s256.is_some());
        if let Some(CurveParams::Secp256k1 { order, generator_projective }) = params_s256 {
            println!("Secp256k1 Order: {}", order.to_str_radix(16));
            assert!(*order > BigInt::zero(), "Secp256k1 order should not be zero");
            assert!(!bool::from(generator_projective.is_identity()), "Secp256k1 generator should not be identity");
        } else {
            panic!("Expected Secp256k1 params");
        }

        let params_ed25519 = get_curve_params(CurveName::Ed25519);
        assert!(params_ed25519.is_some());
        if let Some(CurveParams::Ed25519 { order, generator }) = params_ed25519 {
            println!("Ed25519 Order: {}", order.to_str_radix(16));
            assert!(*order > BigInt::zero(), "Ed25519 order should not be zero");
            assert!(!generator.is_identity(), "Ed25519 generator should not be identity");
        } else {
            panic!("Expected Ed25519 params");
        }
    }

    #[test]
    fn test_same_curve() {
        assert!(same_curve(CurveName::Secp256k1, CurveName::Secp256k1));
        assert!(same_curve(CurveName::Ed25519, CurveName::Ed25519));
        assert!(!same_curve(CurveName::Secp256k1, CurveName::Ed25519));
    }

    #[test]
    fn test_convenience_param_functions() {
        let params_s256 = s256k1_params();
        assert!(matches!(params_s256, CurveParams::Secp256k1 { .. }));

        let params_ed25519 = ed25519_params();
        assert!(matches!(params_ed25519, CurveParams::Ed25519 { .. }));
    }

    #[test]
    fn test_registry_initialization() {
        let registry = get_or_init_registry();
        assert_eq!(registry.len(), 2, "Registry should contain parameters for 2 curves");
        assert!(registry.contains_key(&CurveName::Secp256k1));
        assert!(registry.contains_key(&CurveName::Ed25519));
    }
}
