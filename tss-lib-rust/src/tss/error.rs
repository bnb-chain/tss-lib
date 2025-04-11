// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/tss/error.go

use crate::tss::party_id::PartyID;
use std::fmt;
use thiserror::Error;

/// Represents the specific type of error that occurred within a TSS round.
#[derive(Error, Debug, Clone)] // Clone might be tricky if the boxed error is not Clone
pub enum RoundErr {
    #[error("general error: {0}")]
    General(#[source] Box<dyn std::error::Error + Send + Sync>), // Boxed to allow different underlying types

    #[error("message validation error: {0}")]
    Validation(String),

    #[error("message receive timeout (party: {party_id:?}, round: {round:?})")]
    ReceiveTimeout {
        party_id: Option<PartyID>,
        round: Option<i32>,
    },

    #[error("message processing error: {0}")]
    Processing(String),

    // Add other specific round error types as needed
    #[error("invalid party count: expected {expected}, got {got}")]
    InvalidPartyCount { expected: usize, got: usize },

    #[error("invalid threshold: expected {expected}, got {got}")]
    InvalidThreshold { expected: usize, got: usize },

    #[error("crypto error: {0}")]
    Crypto(String), // Placeholder for more specific crypto errors

    #[error("internal error: {0}")]
    Internal(String),
}


/// A TSS-specific error containing context about the failure.
#[derive(Error, Debug, Clone)] // Clone depends on RoundErr being Clone
// #[error("Task '{task}', Round {round}, Victim {victim:?}, Culprits {culprits:?}: {source}")]
pub struct RoundError {
    #[source] // The underlying error kind
    pub source: RoundErr,

    // Contextual information
    pub task: String,
    pub round: i32, // Use i32 for round number, -1 if not applicable
    pub victim: Option<PartyID>,
    pub culprits: Vec<PartyID>,
}

impl RoundError {
    /// Creates a new `RoundError`.
    pub fn new(
        source: RoundErr,
        task: String,
        round: i32,
        victim: Option<PartyID>,
        culprits: Vec<PartyID>,
    ) -> Self {
        Self { source, task, round, victim, culprits }
    }

    // Convenience constructor for general errors
    pub fn from_error<E: std::error::Error + Send + Sync + 'static>(
        err: E,
        task: String,
        round: i32,
        victim: Option<PartyID>,
        culprits: Vec<PartyID>,
    ) -> Self {
        Self::new(RoundErr::General(Box::new(err)), task, round, victim, culprits)
    }
}

// Custom display implementation
impl fmt::Display for RoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Task '{}', Round {}, ", self.task, self.round)?;
        if let Some(victim) = &self.victim {
            write!(f, "Victim {}, ", victim)?;
        }
        if !self.culprits.is_empty() {
            write!(f, "Culprits {:?}: ", self.culprits)?;
        }
        write!(f, "{}", self.source)
    }
} 