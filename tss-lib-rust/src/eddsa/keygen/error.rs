// Keygen specific errors

use std::fmt;
use crate::tss::party_id::PartyID;

#[derive(Debug, Clone)] // Added Clone
pub enum TssError {
    // Errors specific to keygen
    InvalidPartyIndex { received_index: usize, max_index: usize },
    KeygenVssError { source_error: String },
    SchnorrProofError { source_error: String },
    KeygenRound3VerificationError { party: PartyID, message: String },
    KeygenInvalidPublicKey,
    CurveNotFoundError,
    UnsupportedCurveError,
    PartyIndexNotFound,
    MessageParseError(String),
    UnexpectedMessageReceived,
    ProceedCalledWhenNotReady,

    // More general errors adapted from tss::Error concept
    BaseError { message: String },
    RoundError { message: String, round: u32, culprits: Vec<PartyID> },
    InternalError { message: String },
    LockPoisonError(String),
    ChannelSendError(String),

    // Add other variants as needed
}

// Implement std::error::Error trait
impl std::error::Error for TssError {}

// Implement Display trait for user-friendly messages
impl fmt::Display for TssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TssError::InvalidPartyIndex { received_index, max_index } => 
                write!(f, "Invalid party index received: {}, max index: {}", received_index, max_index),
            TssError::KeygenVssError { source_error } => write!(f, "Keygen VSS error: {}", source_error),
            TssError::SchnorrProofError { source_error } => write!(f, "Schnorr proof error: {}", source_error),
            TssError::KeygenRound3VerificationError { party, message } => 
                write!(f, "Round 3 verification failed for party {:?}: {}", party, message),
            TssError::KeygenInvalidPublicKey => write!(f, "Keygen resulted in invalid public key (identity element)"),
            TssError::CurveNotFoundError => write!(f, "Required elliptic curve parameters not found"),
            TssError::UnsupportedCurveError => write!(f, "Elliptic curve specified is not supported by this protocol"),
            TssError::PartyIndexNotFound => write!(f, "Could not find own party index in parameters"),
            TssError::MessageParseError(s) => write!(f, "Failed to parse message: {}", s),
            TssError::UnexpectedMessageReceived => write!(f, "Received message unexpected in this round/state"),
            TssError::ProceedCalledWhenNotReady => write!(f, "Proceed called before round could proceed"),
            TssError::BaseError { message } => write!(f, "Base party error: {}", message),
            TssError::RoundError { message, round, culprits } => 
                write!(f, "Round {} error (culprits: {:?}): {}", round, culprits, message),
            TssError::InternalError { message } => write!(f, "Internal error: {}", message),
            TssError::LockPoisonError(s) => write!(f, "Mutex lock poison error: {}", s),
            TssError::ChannelSendError(s) => write!(f, "Channel send error: {}", s),
        }
    }
}

// Helper to create a RoundError (can be used by BaseParty::wrap_error)
impl TssError {
    pub fn new_round_error(
        source_err: Box<dyn std::error::Error + Send + Sync + 'static>,
        round: u32,
        culprits: Vec<PartyID>,
    ) -> Self {
        TssError::RoundError {
            message: source_err.to_string(),
            round,
            culprits,
        }
    }
} 