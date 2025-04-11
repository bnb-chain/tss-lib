// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation & adaptation of tss-lib-go/crypto/ecpoint.go

// TODO: Determine the exact curve types needed (k256, p256, ed25519?) and use specific types
//       instead of a generic approach where possible for type safety and performance.
//       This initial translation uses a more generic structure based on traits.

use crate::tss; // Assuming tss module defines the EC() curve access and curve registry
use curve25519_dalek::edwards::CompressedEdwardsY;
use elliptic_curve::scalar::ScalarPrimitive;
use elliptic_curve::{{group::GroupEncoding, point::PointCompression, sec1::{FromEncodedPoint, ToEncodedPoint}}};
use k256::{{AffinePoint as K256AffinePoint, ProjectivePoint as K256ProjectivePoint, Scalar as K256Scalar}};
use p256::{{AffinePoint as P256AffinePoint, ProjectivePoint as P256ProjectivePoint, Scalar as P256Scalar}};

use num_bigint_dig::{{BigInt, Sign}};
use num_traits::{{Zero, One}};
use serde::{{Deserialize, Deserializer, Serialize, Serializer}};
use std::fmt;
use thiserror::Error;

use elliptic_curve::{{Curve, CurveArithmetic, FieldBytesSize, Group, ProjectivePoint, Scalar}};
use elliptic_curve::generic_array::typenum::Unsigned;
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::sec1::EncodedPoint;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PointError {
    #[error("point is not on curve: x={x}, y={y}")]
    NotOnCurve { x: BigInt, y: BigInt },
    #[error("failed to decompress point: {0}")]
    DecompressionError(String),
    #[error("invalid coordinates: x or y is nil")]
    InvalidCoords,
    #[error("flatten/unflatten error: {0}")]
    FlattenError(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("unknown curve name: {0}")]
    UnknownCurve(String),
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
    #[error("point validation failed")]
    ValidationFailed,
}

// --- Generic ECPoint Abstraction (using traits) ---
// This provides a flexible structure but might be less performant/idiomatic
// than using concrete types like K256AffinePoint directly where possible.

#[derive(Clone)] // Need custom Debug, PartialEq, Eq
pub struct ECPoint<C: Curve + CurveArithmetic> where
    Scalar<C>: From<K256Scalar> + From<P256Scalar>, // Example constraint, adjust as needed
    ProjectivePoint<C>: GroupEncoding + Group,
    <C as CurveArithmetic>::AffinePoint: AffineCoordinates<FieldBytesSize = FieldBytesSize<C>> + ToEncodedPoint<C> + FromEncodedPoint<C>,
{
    point: ProjectivePoint<C>, // Store as projective for efficient operations
}

// Manual implementation of Debug
impl<C: Curve + CurveArithmetic> fmt::Debug for ECPoint<C> where
    Scalar<C>: From<K256Scalar> + From<P256Scalar>,
    ProjectivePoint<C>: GroupEncoding + Group,
    <C as CurveArithmetic>::AffinePoint: AffineCoordinates<FieldBytesSize = FieldBytesSize<C>> + ToEncodedPoint<C> + FromEncodedPoint<C> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ECPoint")
         .field("point", &self.point.to_affine()) // Debug affine representation
         .finish()
    }
}

// Manual implementation of PartialEq
impl<C: Curve + CurveArithmetic> PartialEq for ECPoint<C> where
    Scalar<C>: From<K256Scalar> + From<P256Scalar>,
    ProjectivePoint<C>: GroupEncoding + Group,
    <C as CurveArithmetic>::AffinePoint: AffineCoordinates<FieldBytesSize = FieldBytesSize<C>> + ToEncodedPoint<C> + FromEncodedPoint<C>,
{
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point
    }
}
impl<C: Curve + CurveArithmetic> Eq for ECPoint<C> where
    Scalar<C>: From<K256Scalar> + From<P256Scalar>,
    ProjectivePoint<C>: GroupEncoding + Group,
    <C as CurveArithmetic>::AffinePoint: AffineCoordinates<FieldBytesSize = FieldBytesSize<C>> + ToEncodedPoint<C> + FromEncodedPoint<C>,
{}


impl<C: Curve + CurveArithmetic> ECPoint<C> where
    Scalar<C>: From<K256Scalar> + From<P256Scalar> + From<BigInt>,
    ProjectivePoint<C>: GroupEncoding + Group,
    <C as CurveArithmetic>::AffinePoint: AffineCoordinates<FieldBytesSize = FieldBytesSize<C>> + ToEncodedPoint<C> + FromEncodedPoint<C>,
    ScalarPrimitive<C>: From<Scalar<C>>,
{
    /// Creates a new point from affine coordinates (BigInt). Checks if it's on the curve.
    pub fn from_coords(x: &BigInt, y: &BigInt) -> Result<Self, PointError> {
        // TODO: Need a way to convert BigInt x, y to AffinePoint<C>
        // This is non-trivial and curve-specific. The `elliptic-curve` crates
        // primarily work with field elements, not BigInts directly.
        // A temporary, inefficient approach might involve converting BigInt to bytes,
        // then trying to create a FieldElement, then an AffinePoint.
        // This is highly dependent on the specific curve and its field representation.
        // For now, this function is incomplete.
         Err(PointError::InternalError("from_coords BigInt conversion not implemented"))
        /* Example sketch (needs actual implementation):
        let affine_point = coords_to_affine::<C>(x, y)?;
        if bool::from(affine_point.is_identity()) || !bool::from(affine_point.is_on_curve()) {
             Err(PointError::NotOnCurve { x: x.clone(), y: y.clone() })
        } else {
             Ok(Self { point: ProjectivePoint::<C>::from(affine_point) })
        }
        */
    }

    /// Creates a point from projective coordinates without curve check.
    pub fn from_projective_unchecked(point: ProjectivePoint<C>) -> Self {
        Self { point }
    }

    /// Creates a point from affine coordinates without curve check.
    pub fn from_affine_unchecked(point: C::AffinePoint) -> Self {
        Self { point: ProjectivePoint::<C>::from(point) }
    }

    /// Creates a point from compressed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PointError> {
        let encoded = EncodedPoint::<C>::from_bytes(bytes)
            .map_err(|e| PointError::InvalidEncoding(e.to_string()))?;
        let affine = C::AffinePoint::from_encoded_point(&encoded);
        if affine.is_none().into() {
             Err(PointError::DecompressionError("Failed to decode point".to_string()))
        } else {
            Ok(Self::from_affine_unchecked(affine.unwrap()))
        }
    }

    /// Returns the affine representation of the point.
    pub fn to_affine(&self) -> C::AffinePoint {
        self.point.to_affine()
    }

    /// Returns the X coordinate as a BigInt.
    pub fn x(&self) -> BigInt {
        // TODO: Convert affine x-coordinate (FieldElement) to BigInt
        // Requires curve-specific logic.
        let (x_fe, _) = self.to_affine().coordinates().unwrap();
        fe_to_bigint::<C>(x_fe)
    }

    /// Returns the Y coordinate as a BigInt.
    pub fn y(&self) -> BigInt {
        // TODO: Convert affine y-coordinate (FieldElement) to BigInt
        // Requires curve-specific logic.
         let (_, y_fe) = self.to_affine().coordinates().unwrap();
        fe_to_bigint::<C>(y_fe)
    }

    /// Returns the point coordinates as a tuple of BigInts.
    pub fn coords(&self) -> (BigInt, BigInt) {
        (self.x(), self.y())
    }

    /// Returns the underlying projective point.
    pub fn projective(&self) -> &ProjectivePoint<C> {
        &self.point
    }

    /// Adds another point to this point.
    pub fn add(&self, other: &Self) -> Result<Self, PointError> {
        Ok(Self { point: self.point + other.point })
    }

    /// Performs scalar multiplication: k * P.
    pub fn scalar_mul(&self, k: &BigInt) -> Self {
        // TODO: Convert BigInt `k` to Scalar<C>
        // Requires curve-specific logic (e.g., modular reduction).
        let scalar_k: Scalar<C> = k.into(); // Needs `impl From<&BigInt> for Scalar<C>`
        Self { point: self.point * scalar_k }
    }

    /// Checks if the point is the identity element (point at infinity).
    pub fn is_identity(&self) -> bool {
        bool::from(self.point.is_identity())
    }

     /// Performs `self * 8 * 8^-1`. Only relevant for EdDSA cofactor clearing?
     /// Needs curve-specific `EIGHT_INV` constant.
     pub fn eight_inv_eight(&self) -> Self {
         // TODO: Implement based on curve specifics if needed
         // let eight = Scalar::<C>::from(8u8); // Check if this conversion works
         // let eight_inv = EIGHT_INV::<C>(); // Needs curve-specific constant
         // Self { point: self.point * eight * eight_inv }
         self.clone() // Placeholder
     }

    /// Validates that the point is not identity and is on the curve.
    pub fn validate_basic(&self) -> bool {
        !self.is_identity() // Projective points are always on the curve by construction
    }

    /// Serializes the point to compressed bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_affine().to_encoded_point(true).to_bytes().to_vec()
    }

    // --- Methods corresponding to Go funcs ---

    /// Multiplies the curve's generator by a scalar `k`.
    pub fn scalar_base_mult(k: &BigInt) -> Self {
         // TODO: Convert BigInt `k` to Scalar<C>
        let scalar_k: Scalar<C> = k.into();
        Self { point: ProjectivePoint::<C>::generator() * scalar_k }
    }
}

// --- BigInt / FieldElement Conversion Helpers (Placeholders) ---
// These need concrete implementations for each supported curve.

fn fe_to_bigint<C: Curve + CurveArithmetic>(fe: C::FieldElement) -> BigInt {
    // Placeholder: Convert FieldElement to bytes, then to BigInt
    // This assumes a specific byte representation (e.g., big-endian)
    BigInt::from_bytes_be(Sign::Plus, &fe.to_bytes())
}

fn bigint_to_fe<C: Curve + CurveArithmetic>(bi: &BigInt) -> C::FieldElement {
    // Placeholder: Convert BigInt to bytes, then to FieldElement
    // This is complex due to field size and potential modular reduction.
    // Requires careful implementation based on curve specs.
    let bytes = bi.to_bytes_be().1;
    // Need logic to pad/truncate bytes to FieldBytesSize<C>
    // C::FieldElement::from_bytes(&field_bytes).unwrap() // Simplified
    unimplemented!("bigint_to_fe conversion needed")
}

impl<C: Curve + CurveArithmetic> TryFrom<&BigInt> for Scalar<C> where
    // Constraints from ECPoint
     Scalar<C>: From<K256Scalar> + From<P256Scalar> + From<BigInt>,
     ProjectivePoint<C>: GroupEncoding + Group,
     <C as CurveArithmetic>::AffinePoint: AffineCoordinates<FieldBytesSize = FieldBytesSize<C>> + ToEncodedPoint<C> + FromEncodedPoint<C>,
     ScalarPrimitive<C>: From<Scalar<C>>,
{
    type Error = PointError;

    fn try_from(value: &BigInt) -> Result<Self, Self::Error> {
        // TODO: Proper BigInt to Scalar conversion with modular reduction
        // let modulus = C::ORDER; // Need a way to get modulus BigInt
        // let reduced_bi = value.modpow(&BigInt::one(), &modulus);
        // Scalar::<C>::from_repr(reduced_bi.to_bytes_be().1) // Simplified
        Err(PointError::InternalError("BigInt to Scalar conversion not implemented"))
    }
}

impl<C: Curve + CurveArithmetic> From<Scalar<C>> for BigInt where
    // Constraints from ECPoint
     Scalar<C>: From<K256Scalar> + From<P256Scalar>,
     ProjectivePoint<C>: GroupEncoding + Group,
     <C as CurveArithmetic>::AffinePoint: AffineCoordinates<FieldBytesSize = FieldBytesSize<C>> + ToEncodedPoint<C> + FromEncodedPoint<C>,
     ScalarPrimitive<C>: From<Scalar<C>>,
{
     fn from(scalar: Scalar<C>) -> Self {
         // TODO: Proper Scalar to BigInt conversion
         // BigInt::from_bytes_be(Sign::Plus, &scalar.to_repr())
         unimplemented!("Scalar to BigInt conversion needed")
     }
 }


// --- Flatten/Unflatten --- //

pub fn flatten_ec_points<C>(points: &[ECPoint<C>]) -> Result<Vec<BigInt>, PointError>
where
    C: Curve + CurveArithmetic,
    Scalar<C>: From<K256Scalar> + From<P256Scalar> + From<BigInt>,
    ProjectivePoint<C>: GroupEncoding + Group,
    <C as CurveArithmetic>::AffinePoint: AffineCoordinates<FieldBytesSize = FieldBytesSize<C>> + ToEncodedPoint<C> + FromEncodedPoint<C>,
    ScalarPrimitive<C>: From<Scalar<C>>,
{
    let mut flat = Vec::with_capacity(points.len() * 2);
    for point in points {
        if point.is_identity() {
            // Decide how to handle identity points (e.g., error or represent as (0,0)?)
            return Err(PointError::FlattenError("Cannot flatten identity point".to_string()));
        }
        let (x, y) = point.coords();
        flat.push(x);
        flat.push(y);
    }
    Ok(flat)
}

pub fn un_flatten_ec_points<C>(
    coords: &[BigInt],
    _no_curve_check: bool, // Curve check happens in from_coords
) -> Result<Vec<ECPoint<C>>, PointError>
where
    C: Curve + CurveArithmetic,
    Scalar<C>: From<K256Scalar> + From<P256Scalar> + From<BigInt>,
    ProjectivePoint<C>: GroupEncoding + Group,
    <C as CurveArithmetic>::AffinePoint: AffineCoordinates<FieldBytesSize = FieldBytesSize<C>> + ToEncodedPoint<C> + FromEncodedPoint<C>,
    ScalarPrimitive<C>: From<Scalar<C>>,
{
    if coords.len() % 2 != 0 {
        return Err(PointError::FlattenError("Input length must be even".to_string()));
    }
    let mut un_flat = Vec::with_capacity(coords.len() / 2);
    for i in (0..coords.len()).step_by(2) {
        let x = &coords[i];
        let y = &coords[i + 1];
        // Note: from_coords currently unimplemented for BigInt
        let point = ECPoint::<C>::from_coords(x, y)?;
        un_flat.push(point);
    }
    Ok(un_flat)
}


// --- Serialization (Example using Serde) ---
// This requires enabling features on the curve crates (e.g., `k256/serde`)
// and potentially custom logic if the default representation isn't suitable.

impl<C> Serialize for ECPoint<C>
where
    C: Curve + CurveArithmetic + 'static, // Add 'static bound
    Scalar<C>: From<K256Scalar> + From<P256Scalar> + From<BigInt>,
    ProjectivePoint<C>: GroupEncoding + Group,
    <C as CurveArithmetic>::AffinePoint: Serialize + AffineCoordinates<FieldBytesSize = FieldBytesSize<C>> + ToEncodedPoint<C> + FromEncodedPoint<C>,
    ScalarPrimitive<C>: From<Scalar<C>>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Get curve name from a registry (needs implementation)
        let curve_name = tss::get_curve_name::<C>().map_err(serde::ser::Error::custom)?;

        // Serialize affine point using its derived Serialize impl
        #[derive(Serialize)]
        struct Helper<'a, P: Serialize> {
            curve: tss::CurveName,
            point: &'a P,
        }

        let helper = Helper { curve: curve_name, point: &self.to_affine() };
        helper.serialize(serializer)
        // // Alternative: Serialize compressed bytes
        // serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de, C> Deserialize<'de> for ECPoint<C>
where
    C: Curve + CurveArithmetic + 'static, // Add 'static bound
    Scalar<C>: From<K256Scalar> + From<P256Scalar> + From<BigInt>,
    ProjectivePoint<C>: GroupEncoding + Group,
    <C as CurveArithmetic>::AffinePoint: Deserialize<'de> + AffineCoordinates<FieldBytesSize = FieldBytesSize<C>> + ToEncodedPoint<C> + FromEncodedPoint<C>,
    ScalarPrimitive<C>: From<Scalar<C>>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper<P: Deserialize<'de>> {
             curve: tss::CurveName,
             point: P,
         }

        let helper = Helper::<C::AffinePoint>::deserialize(deserializer)?;

        // Verify curve name matches C (needs registry)
        // if tss::get_curve_by_name(helper.curve) != Some(Curve::get_instance()) { ... }
         let expected_curve_name = tss::get_curve_name::<C>().map_err(serde::de::Error::custom)?;
         if helper.curve != expected_curve_name {
             return Err(serde::de::Error::custom(format!(
                 "Mismatched curve during deserialization: expected {:?}, got {:?}",
                 expected_curve_name,
                 helper.curve
             )));
         }

        Ok(Self::from_affine_unchecked(helper.point))
        // // Alternative: Deserialize from bytes
        // let bytes = <&[u8]>::deserialize(deserializer)?;
        // Self::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}


// --- Concrete Type Aliases (Example) ---
// Using specific types is generally preferred in application code.

pub type K256Point = ECPoint<k256::Secp256k1>;
pub type P256Point = ECPoint<p256::NistP256>;
// pub type Ed25519Point = ECPoint<curve25519_dalek::> // Needs different trait bounds?

// --- Tests (Illustrative - Requires concrete types and helper implementations) ---

#[cfg(test)]
mod tests {
    use super::*;
    use k256::Secp256k1;
    use elliptic_curve::group::Group;
    use rand::thread_rng;

    // Helper to create a K256 Scalar from BigInt (Placeholder)
    fn k256_scalar_from_bigint(k: &BigInt) -> K256Scalar {
        // WARNING: This is insecure - needs proper modular reduction!
        let bytes = k.to_bytes_be().1;
        // Pad or truncate bytes to 32 bytes for scalar repr
        let mut scalar_bytes = [0u8; 32];
        let start = if bytes.len() > 32 { bytes.len() - 32 } else { 0 };
        let len = std::cmp::min(bytes.len(), 32);
        scalar_bytes[32 - len..].copy_from_slice(&bytes[start..start+len]);

        let primitive: ScalarPrimitive<Secp256k1> = elliptic_curve::ScalarPrimitive::from_slice(&scalar_bytes).unwrap();
        K256Scalar::from(primitive) // Insecure conversion
    }

    #[test]
    fn test_k256_point_ops() {
        let mut rng = thread_rng();
        let scalar1 = K256Scalar::random(&mut rng);
        let scalar2 = K256Scalar::random(&mut rng);

        let p1 = K256Point { point: K256ProjectivePoint::generator() * scalar1 };
        let p2 = K256Point { point: K256ProjectivePoint::generator() * scalar2 };

        // Addition
        let p_sum_expected = K256Point { point: K256ProjectivePoint::generator() * (scalar1 + scalar2) };
        let p_sum_actual = p1.add(&p2).unwrap();
        assert_eq!(p_sum_expected, p_sum_actual);

        // Scalar Mult (using placeholder scalar conversion)
        let k_bi = BigInt::from(123456789u64);
        let k_scalar = k256_scalar_from_bigint(&k_bi);

        let p1_mul_k_expected = K256Point { point: p1.point * k_scalar };
        let p1_mul_k_actual = p1.scalar_mul(&k_bi);
        assert_eq!(p1_mul_k_expected, p1_mul_k_actual);

        // Base Mult (using placeholder scalar conversion)
        let base_mul_k_expected = K256Point { point: K256ProjectivePoint::generator() * k_scalar };
        let base_mul_k_actual = K256Point::scalar_base_mult(&k_bi);
        assert_eq!(base_mul_k_expected, base_mul_k_actual);

        // Identity
        assert!(!p1.is_identity());
        let identity = K256Point { point: K256ProjectivePoint::identity() };
        assert!(identity.is_identity());

        // Validation
        assert!(p1.validate_basic());
        assert!(!identity.validate_basic());
    }

     #[test]
     fn test_k256_bytes_conversion() {
         let mut rng = thread_rng();
         let scalar = K256Scalar::random(&mut rng);
         let p1 = K256Point { point: K256ProjectivePoint::generator() * scalar };

         let bytes = p1.to_bytes();
         println!("Serialized point: {:x?}", bytes);
         assert!(bytes.len() == 33); // Compressed point size for k256

         let p2 = K256Point::from_bytes(&bytes).unwrap();
         assert_eq!(p1, p2);
     }

     // Add tests for flatten/unflatten, serde once helpers are implemented
} 