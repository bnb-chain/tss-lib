// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/tss/curve.go

use std::fmt;
use thiserror::Error;
use serde::{Serialize, Deserialize};

// Re-export curves from dependencies for easier use
pub use k256::{Secp256k1};
pub use ed25519_dalek::curve25519::WrappedEdwards;

/// Enum representing supported elliptic curves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Curve {
    Secp256k1,
    Ed25519,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CurveError {
    #[error("Unsupported curve type")]
    UnsupportedCurve,
    #[error("Curve mismatch")]
    CurveMismatch,
}

impl Curve {
    /// Returns the string representation of the curve name.
    pub fn name(&self) -> &'static str {
        match self {
            Curve::Secp256k1 => "secp256k1",
            Curve::Ed25519 => "ed25519",
        }
    }

    /// Returns the curve enum variant from its string name.
    pub fn from_name(name: &str) -> Result<Self, CurveError> {
        match name {
            "secp256k1" => Ok(Curve::Secp256k1),
            "ed25519" => Ok(Curve::Ed25519),
            _ => Err(CurveError::UnsupportedCurve),
        }
    }

    // --- Methods related to curve properties (example) ---

    /// Returns the order of the curve's base field generator (scalar field size).
    pub fn order(&self) -> num_bigint_dig::BigInt {
        match self {
            Curve::Secp256k1 => {
                let order_bytes = k256::Scalar::ORDER.to_be_bytes();
                num_bigint_dig::BigInt::from_bytes_be(num_bigint_dig::Sign::Plus, &order_bytes)
            }
            Curve::Ed25519 => {
                 // ed25519_dalek::constants::ED25519_ORDER is private, use scalar field modulus
                 let order_bytes = ed25519_dalek::constants::BASEPOINT_ORDER.to_bytes();
                 num_bigint_dig::BigInt::from_bytes_be(num_bigint_dig::Sign::Plus, &order_bytes)
            }
        }
    }

     /// Returns the bit length of the curve order.
    pub fn order_bit_len(&self) -> usize {
        match self {
            Curve::Secp256k1 => 256, // k256::FieldBytesSize::USIZE * 8, but const
            Curve::Ed25519 => 253, // Order L is slightly less than 256 bits
        }
    }

    // Add other necessary curve-specific methods here, e.g.,
    // - get_generator()
    // - is_on_curve(point)
    // - scalar_base_mult(scalar)
    // - point_add(p1, p2)
    // - point_double(p)
    // These might be better placed in the ECPoint abstraction if it's curve-generic.
}

impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}


// Consider if a global default curve is needed like in Go, or if it's better
// to pass the curve type explicitly where needed.
// Rust often prefers explicit dependencies over global mutable state.
// static DEFAULT_CURVE: std::sync::OnceLock<Curve> = std::sync::OnceLock::new();
// pub fn get_default_curve() -> Curve { *DEFAULT_CURVE.get_or_init(|| Curve::Secp256k1) }
// pub fn set_default_curve(curve: Curve) { let _ = DEFAULT_CURVE.set(curve); }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_names() {
        assert_eq!(Curve::Secp256k1.name(), "secp256k1");
        assert_eq!(Curve::Ed25519.name(), "ed25519");

        assert_eq!(Curve::from_name("secp256k1"), Ok(Curve::Secp256k1));
        assert_eq!(Curve::from_name("ed25519"), Ok(Curve::Ed25519));
        assert!(Curve::from_name("invalid").is_err());
    }

    #[test]
    fn test_curve_order() {
        let secp_order = Curve::Secp256k1.order();
        let ed_order = Curve::Ed25519.order();

        println!("Secp256k1 Order: {}", secp_order);
        println!("Ed25519 Order:   {}", ed_order);

        assert!(secp_order > BigInt::zero());
        assert!(ed_order > BigInt::zero());

        // Check against known constants if available/stable
        let expected_secp_order = BigInt::from_str_radix(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
        ).unwrap();
        // Ed25519 order L = 2^252 + 27742317777372353535851937790883648493
         let expected_ed_order = BigInt::from(2u32).pow(252) +
             BigInt::from_str_radix("27742317777372353535851937790883648493", 10).unwrap();

        assert_eq!(secp_order, expected_secp_order);
         assert_eq!(ed_order, expected_ed_order);

         assert_eq!(Curve::Secp256k1.order_bit_len(), 256);
         assert_eq!(Curve::Ed25519.order_bit_len(), 253); // Based on actual order L
    }
} 