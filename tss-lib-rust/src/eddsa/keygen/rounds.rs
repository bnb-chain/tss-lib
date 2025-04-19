// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// EDDSA Keygen round base logic (adapted from Go)

use std::sync::{Arc, Mutex};
use crate::eddsa::keygen::{
    KeygenPartyTmpData,
    KeyGenPartySaveData,
};
use crate::tss::{
    error::TssError,
    message::ParsedMessage, // Import actual ParsedMessage
    params::Parameters,
    party::Round as TssRound, // Import the actual Round trait
    party_id::{PartyID, SortedPartyIDs},
};
use num_bigint::BigInt;
use std::error::Error as StdError;
use std::fmt::Debug;

// Removed placeholder RoundCtx, RoundState
// Removed placeholder get_ssid (logic might move into rounds or be part of context)
// Removed placeholder CurveParams and common_crypto (real types needed)

// Constant for the protocol name
pub const PROTOCOL_NAME: &str = "eddsa-keygen";

// Define the concrete Round trait implementations need access to shared state.
// This was previously handled by RoundCtx. Now rounds will likely hold Arcs.
// Example common structure for a round:
pub trait KeygenRound: TssRound + Debug + Send + Sync {
    // Add methods specific to keygen rounds if needed,
    // otherwise just rely on TssRound.

    // Accessor for temporary data store
    fn temp(&self) -> Arc<Mutex<KeygenPartyTmpData>>;
    // Accessor for persistent save data store
    fn data(&self) -> Arc<Mutex<KeyGenPartySaveData>>;

     // Default wrap_error implementation using stored parameters and round number
     fn wrap_keygen_error(&self, err: Box<dyn StdError>, culprits: Vec<PartyID>) -> TssError {
        TssError::new(
            err,
            PROTOCOL_NAME.to_string(),
            self.round_number(),
            Some(self.params().party_id().clone()), // Get local party ID from params
            culprits,
        )
    }
}


// Note: The TssRound trait from tss/party.rs seems minimal.
// Implementations will likely need internal state management (like RoundState)
// and access to shared message storage (via temp/data Arcs) to fulfill
// the expected logic of `update`, `waiting_for`, `can_proceed`, etc.
