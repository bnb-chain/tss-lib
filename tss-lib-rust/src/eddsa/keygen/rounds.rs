// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// EDDSA Keygen round base logic (adapted from Go)

use std::sync::{Arc, Mutex};
use crate::eddsa::keygen::{
    KeygenPartyTempData,
    KeygenPartySaveData,
    Parameters,
};
use crate::tss::{
    curve::{CurveName, get_curve_params, CurveParams},
    error::TssError,
    message::ParsedMessage, // Import actual ParsedMessage
    party::Round as TssRound, // Import the actual Round trait
    party_id::{PartyID, SortedPartyIDs},
};
use num_bigint::BigInt;
use std::error::Error as StdError;
use std::fmt::Debug;
use crate::crypto::hashing::sha512_256_bytes_to_bytes; // Assuming this hash function exists

// Removed placeholder RoundCtx, RoundState
// Removed placeholder get_ssid (logic might move into rounds or be part of context)
// Removed placeholder CurveParams and common_crypto (real types needed)

// Constant for the protocol name
pub const PROTOCOL_NAME: &str = "eddsa-keygen";

// Define the new KeygenRound trait
pub trait KeygenRound: Debug + Send + Sync {
    // Get the round number (1, 2, 3, ...)
    fn round_number(&self) -> u32;

    // Access the underlying BaseParty
    // TODO: Consider if exposing the whole BaseParty is ideal, or just specific methods.
    // For now, expose it for easier access during refactoring.
    fn base(&self) -> &BaseParty;
    fn base_mut(&mut self) -> &mut BaseParty; // For methods like reset_ok, set_ok

    // Start the round logic (generate/send messages)
    fn start(&mut self) -> Result<(), TssError>;

    // Store an incoming message relevant to this round
    // Note: Content parsing might happen in LocalParty before calling this.
    // This method might just validate type and call base.set_ok().
    fn store_message(&mut self, msg: ParsedMessage) -> Result<(), TssError>;

    // Check if the round has enough messages/state to proceed
    fn can_proceed(&self) -> bool;

    // Perform cryptographic checks and state updates for the round end
    fn proceed(&mut self) -> Result<(), TssError>;

    // Determine the next round
    // Returns None if this is the final round.
    fn next_round(self: Box<Self>) -> Option<Box<dyn KeygenRound>>;
}

// Note: The TssRound trait from tss/party.rs seems minimal.
// Implementations will likely need internal state management (like RoundState)
// and access to shared message storage (via temp/data Arcs) to fulfill
// the expected logic of `update`, `waiting_for`, `can_proceed`, etc.

// get ssid from local params - moved from round_1.rs
// Corresponds to Go's (*base) getSSID()
pub fn get_ssid(params: &Parameters, current_round_num: u32, ssid_nonce: &BigInt) -> Result<Vec<u8>, TssError> {
    // curve params need to be retrieved based on params.curve
    let curve = get_curve_params(params.curve())
        .ok_or_else(|| TssError::CurveNotFoundError)?; // Use appropriate error

    let curve_params_bytes: Vec<Vec<u8>> = match curve {
        CurveParams::Ed25519 { order, generator } => {
            // For Ed25519, the Go code uses P, N, Gx, Gy.
            // Let's use order and generator point representation.
            // TODO: Confirm exact byte representation needed to match Go hash.
             vec![
                 order.to_bytes_be().1, // N
                 generator.compress().to_bytes().to_vec(), // Compressed G
             ]
        },
        CurveParams::Secp256k1 { order, generator_projective } => {
            // Use P, N, Gx, Gy for secp256k1 if matching Go's ECDSA getSSID is needed
            // This function is specific to EDDSA keygen, so maybe error here?
            return Err(TssError::UnsupportedCurveError);
        }
    };

    let party_keys_bytes: Vec<Vec<u8>> = params.parties().iter()
        .map(|p| p.key().to_bytes_be().1)
        .collect();

    let round_num_bytes = BigInt::from(current_round_num).to_bytes_be().1;
    let nonce_bytes = ssid_nonce.to_bytes_be().1;

    // Combine all byte slices for hashing
    let mut bytes_to_hash: Vec<&[u8]> = Vec::new();
    for param_bytes in &curve_params_bytes {
        bytes_to_hash.push(param_bytes.as_slice());
    }
    for key_bytes in &party_keys_bytes {
        bytes_to_hash.push(key_bytes.as_slice());
    }
    bytes_to_hash.push(&round_num_bytes);
    bytes_to_hash.push(&nonce_bytes);

    // Perform the hash
    // TODO: Ensure sha512_256_bytes_to_bytes matches Go's common.SHA512_256i(...).Bytes()
    let ssid = sha512_256_bytes_to_bytes(&bytes_to_hash);

    Ok(ssid)
}
