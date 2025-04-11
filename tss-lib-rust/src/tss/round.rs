// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/tss/round.go

use crate::tss::{
    error::{RoundError, RoundErr},
    message::ParsedMessage,
    params::Parameters,
    party_id::PartyID,
};
use std::{{
    fmt::Debug,
    sync::Arc,
    error::Error as StdError,
}};

/// Represents a single round within a TSS protocol.
pub trait Round: Send + Sync + Debug {
    /// Returns the parameters used for this round/protocol.
    fn params(&self) -> &Parameters;

    /// Starts the round logic (e.g., sending initial messages).
    fn start(&self) -> Result<(), RoundError>;

    /// Updates the round state based on stored messages.
    /// Returns Ok(true) if the state was updated, Ok(false) otherwise.
    fn update(&self) -> Result<bool, RoundError>;

    /// Returns the current round number (1-based typically).
    fn round_number(&self) -> i32;

    /// Checks if the message can be accepted by the current round (e.g., based on round number).
    fn can_accept(&self, msg: &ParsedMessage) -> bool;

    /// Checks if the round has enough messages/state to proceed to the next round.
    fn can_proceed(&self) -> bool;

    /// Returns the next round in the protocol, or None if this is the final round.
    fn next_round(&self) -> Option<Arc<dyn Round>>;

    /// Returns the list of parties that this round is currently waiting for messages from.
    fn waiting_for(&self) -> Vec<PartyID>;

    /// Wraps a standard error into a `RoundError` specific to this round.
    fn wrap_error<E: StdError + Send + Sync + 'static>(&self, err: E, culprits: Vec<PartyID>) -> RoundError {
        RoundError::new(
            RoundErr::General(Box::new(err)),
            self.params().party_id().id.clone(), // Assuming task name = party id for now?
            self.round_number(),
            Some(self.params().party_id().as_ref().clone()),
            culprits,
        )
    }
} 