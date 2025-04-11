// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/tss/party.go

use crate::{
    common::{self, logging::*},
    tss::{
        message::ParsedMessage,
        round::{Round, RoundErr, RoundError},
        party_id::PartyID,
    }
};

use std::{
    fmt::Debug,
    sync::{Arc, Mutex, RwLock},
    error::Error as StdError,
};
use tracing::debug;

// Forward declaration if Round uses Party
// use crate::tss::round::Round; // Consider if needed

/// A trait representing a participant (party) in a TSS protocol round.
pub trait Party: Send + Sync + Debug {
    /// Starts the first round of the protocol for this party.
    fn start(&self) -> Result<(), RoundError>;

    /// Updates the party state from received wire bytes.
    /// is_broadcast indicates if the message was received via reliable broadcast.
    fn update_from_bytes(
        &self,
        wire_bytes: &[u8],
        from: &PartyID,
        is_broadcast: bool,
    ) -> Result<bool, RoundError>;

    /// Updates the party state from a parsed message (for local execution/tests).
    fn update(&self, msg: ParsedMessage) -> Result<bool, RoundError>;

    /// Returns true if the party is currently executing a round.
    fn is_running(&self) -> bool;

    /// Returns the list of parties that this party is currently waiting for messages from.
    fn waiting_for(&self) -> Vec<PartyID>;

    /// Validates an incoming message.
    fn validate_message(&self, msg: &ParsedMessage) -> Result<bool, RoundError>;

    /// Stores a validated message, possibly in the current round's state.
    fn store_message(&self, msg: ParsedMessage) -> Result<bool, RoundError>;

    /// Returns the initial round for this protocol execution.
    fn first_round(&self) -> Arc<dyn Round>;

    /// Wraps a standard error into a `RoundError`, associating it with culprits.
    fn wrap_error<E: StdError + 'static>(
        &self,
        error: E,
        culprits: Vec<PartyID>,
    ) -> RoundError;

    /// Returns the `PartyID` of this party.
    fn party_id(&self) -> &PartyID;

    /// Provides a string representation of the party's current state.
    fn string(&self) -> String;

    // --- Internal lifecycle methods (consider if they need to be public or part of an internal trait) ---

    /// Sets the current round for the party.
    /// Returns an error if a round is already set.
    fn set_round(&self, round: Arc<dyn Round>) -> Result<(), RoundError>;

    /// Gets the current round.
    fn current_round(&self) -> Option<Arc<dyn Round>>;

    /// Advances to the next round.
    fn advance_round(&self);

    // Note: Locking is handled differently in Rust. Typically, data is protected by Mutex/RwLock.
    // Explicit lock/unlock methods are less common than accessing data through lock guards.
    // If granular locking is truly needed, these might be necessary, but consider alternatives.
    // fn lock(&self);
    // fn unlock(&self);
}


/// A base implementation of the `Party` trait, holding common state.
#[derive(Debug)]
pub struct BaseParty {
     // Use Arc<Mutex<...>> or Arc<RwLock<...>> for shared mutable state
     // The current round needs to be mutable and shared.
    current_round: Arc<RwLock<Option<Arc<dyn Round>>>>, // Option because it starts as None
    first_round_provider: Arc<dyn Fn() -> Arc<dyn Round> + Send + Sync>,
    party_id: PartyID,
}

impl BaseParty {
    pub fn new(
        party_id: PartyID,
         first_round_provider: Arc<dyn Fn() -> Arc<dyn Round> + Send + Sync>,
    ) -> Self {
        Self {
            current_round: Arc::new(RwLock::new(None)),
            first_round_provider,
            party_id,
        }
    }

    /// Helper to get the current round locked for reading.
    fn get_current_round_read(&self) -> Option<Arc<dyn Round>> {
        self.current_round.read().unwrap().clone()
    }

    // --- Default implementations for some Party methods ---

    pub fn default_is_running(&self) -> bool {
        self.get_current_round_read().is_some()
    }

    pub fn default_waiting_for(&self) -> Vec<PartyID> {
        match self.get_current_round_read() {
            Some(round) => round.waiting_for(),
            None => Vec::new(),
        }
    }

    pub fn default_wrap_error<E: StdError + 'static>(
        &self,
        error: E,
        culprits: Vec<PartyID>,
    ) -> RoundError {
         match self.get_current_round_read() {
            Some(round) => round.wrap_error(error, culprits),
            None => RoundError::new(RoundErr::General(Box::new(error)), "".to_string(), -1, None, culprits),
         }
    }

    pub fn default_validate_message(&self, msg: &ParsedMessage) -> Result<bool, RoundError> {
        if msg.content.is_none() {
            return Err(self.default_wrap_error(anyhow::anyhow!("received nil msg content: {:?}", msg), vec![]));
        }
        if msg.from.is_none() || !msg.from.as_ref().unwrap().validate_basic() {
             return Err(self.default_wrap_error(anyhow::anyhow!("received msg with invalid sender: {:?}", msg), vec![]));
        }
        if !msg.validate_basic() {
             let culprit = msg.from.clone();
             return Err(self.default_wrap_error(anyhow::anyhow!("message failed ValidateBasic: {:?}", msg), culprit.map_or(vec![], |c| vec![c])));
        }
        Ok(true)
    }

    pub fn default_string(&self) -> String {
         match self.get_current_round_read() {
            Some(round) => format!("round: {}", round.round_number()),
            None => "Not running (no current round)".to_string(),
        }
    }

    // --- Default implementations for internal lifecycle methods ---

    pub fn default_set_round(&self, round: Arc<dyn Round>) -> Result<(), RoundError> {
        let mut current_round_guard = self.current_round.write().unwrap();
        if current_round_guard.is_some() {
            Err(self.default_wrap_error(anyhow::anyhow!("a round is already set on this party"), vec![]))
        } else {
            *current_round_guard = Some(round);
            Ok(())
        }
    }

    pub fn default_current_round(&self) -> Option<Arc<dyn Round>> {
        self.get_current_round_read()
    }

    pub fn default_advance_round(&self) {
        let mut current_round_guard = self.current_round.write().unwrap();
        if let Some(current) = current_round_guard.take() { // Take ownership
            *current_round_guard = current.next_round(); // Set the next round
        } else {
             error!(target: "tss-lib", party_id=?self.party_id, "Attempted to advance round when no round was set");
            // Or panic, or return error? Depending on expected state guarantees.
        }
    }

     pub fn default_party_id(&self) -> &PartyID {
        &self.party_id
    }

     pub fn default_first_round(&self) -> Arc<dyn Round> {
        (self.first_round_provider)()
    }
}

// ----- Helper functions analogous to BaseStart and BaseUpdate -----
// These need to be adapted based on how the specific Party implementations handle state and rounds.
// They likely belong within the specific Party implementation (e.g., KeygenParty, SigningParty)
// rather than being general free functions.

pub fn base_start(
    party: &(impl Party + ?Sized),
    task_name: &str,
    // Optional prepare function (takes the first round)
    prepare: Option<&dyn Fn(Arc<dyn Round>) -> Result<(), RoundError>>,
) -> Result<(), RoundError> {
    // Locking is implicitly handled by accessing shared state through Mutex/RwLock

    if !party.party_id().validate_basic() {
         return Err(party.wrap_error(anyhow::anyhow!("could not start. this party has an invalid PartyID: {:?}", party.party_id()), vec![]));
    }
    if party.is_running() {
         return Err(party.wrap_error(anyhow::anyhow!("could not start. party is already running"), vec![]));
    }

    let first_round = party.first_round();
    party.set_round(first_round.clone())?; // Set the round internally

    if let Some(prep_fn) = prepare {
        prep_fn(first_round.clone())?;
    }

    info!(target: "tss-lib", party_id = ?party.party_id(), task = task_name, round = 1, "starting");

    // The round start might involve sending initial messages
    let start_result = first_round.start();

    info!(target: "tss-lib", party_id = ?party.party_id(), task = task_name, round = 1, "finished initial processing");

    start_result
}

pub fn base_update(
    party: &(impl Party + ?Sized),
    msg: ParsedMessage,
    task_name: &str,
) -> Result<bool, RoundError> {
    party.validate_message(&msg)?; // Fail fast

    debug!(target: "tss-lib", party_id = ?party.party_id(), message = ?msg, "received message");

    // Store the message first. This might update round state.
    party.store_message(msg.clone())?;

    // Loop to process rounds as long as they can proceed
    loop {
        let current_round_opt = party.current_round();
        if current_round_opt.is_none() {
            debug!(target: "tss-lib", party_id = ?party.party_id(), task = task_name, "Update called but party not running");
            return Ok(true); // Not running, but message stored? Or error?
        }
        let current_round = current_round_opt.unwrap();
        let round_num = current_round.round_number();

        debug!(target: "tss-lib", party_id = ?party.party_id(), task = task_name, round = round_num, message = ?msg, "update");

        // Attempt to update the current round state
        current_round.update()?;

        if current_round.can_proceed() {
             info!(target: "tss-lib", party_id = ?party.party_id(), task = task_name, round = round_num, "round finished, advancing");
            party.advance_round();

            if let Some(next_round) = party.current_round() {
                let next_round_num = next_round.round_number();
                 info!(target: "tss-lib", party_id = ?party.party_id(), task = task_name, round = next_round_num, "starting next round");
                next_round.start()?;
                 // Continue the loop to process potential auto-execution in the new round
                 continue;
            } else {
                 // Protocol finished
                 info!(target: "tss-lib", party_id = ?party.party_id(), task = task_name, "protocol finished!");
                 return Ok(true);
            }
        } else {
             // Round cannot proceed yet (waiting for more messages)
             debug!(target: "tss-lib", party_id = ?party.party_id(), task = task_name, round = round_num, "waiting for more messages");
            return Ok(true);
        }
    }
} 