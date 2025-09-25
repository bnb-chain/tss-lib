// EDDSA Keygen protocol messages (ported from eddsa-keygen.pb.go)
// Use prost for protobuf compatibility (assuming eddsa-keygen.proto exists)

use prost::Message;
use num_bigint::BigInt;

// Keygen specific imports
use crate::eddsa::keygen::TssError;

// TSS core imports
use crate::tss::message::{MessageContent}; // Use tss trait
use crate::tss::party_id::PartyID;

// Crypto imports
use crate::crypto::commitments::hash_commit_decommit::{Commitment as HashCommitment, Decommitment as HashDeCommitment};
use crate::crypto::vss::Share as VssShare; // Use actual VssShare type
use crate::crypto::schnorr::Proof as SchnorrProof; // Use actual SchnorrProof type
use ed25519_dalek::EdwardsPoint; // Use concrete point type

// --- Remove Placeholders --- //
/*
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)] pub struct CommitmentPlaceholder(pub Vec<u8>);
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)] pub struct DecommitmentPlaceholder(pub Vec<Vec<u8>>);
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)] pub struct VssSharePlaceholder(pub Vec<u8>);
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)] pub struct PointPlaceholder { pub x: Vec<u8>, pub y: Vec<u8> };
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)] pub struct SchnorrProofPlaceholder { pub alpha: PointPlaceholder, pub t: Vec<u8> };
*/
// --- End Placeholders --- //

// Corresponds to KGRound1Message in Go protobuf
#[derive(Clone, PartialEq, Message)]
pub struct KGRound1Message {
    #[prost(bytes="vec", tag="1")]
    pub commitment: Vec<u8>,
}

impl KGRound1Message {
    pub fn validate(&self) -> bool {
        !self.commitment.is_empty()
    }

    // Corresponds to Go UnmarshalCommitment()
    pub fn unmarshal_commitment(&self) -> BigInt {
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &self.commitment)
    }
}

// Define trait implementation for MessageContent
impl MessageContent for KGRound1Message {
    fn validate_basic(&self) -> bool { self.validate() }
    // Implement other methods as needed (e.g., short_name)
}


// Corresponds to KGRound2Message1 in Go protobuf
#[derive(Clone, PartialEq, Message)]
pub struct KGRound2Message1 {
    #[prost(bytes="vec", tag="1")]
    pub share: Vec<u8>, // Assuming VssShare bytes
}

impl KGRound2Message1 {
    pub fn validate(&self) -> bool {
        !self.share.is_empty()
    }

    // Corresponds to Go UnmarshalShare()
    pub fn unmarshal_share(&self) -> BigInt {
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &self.share)
    }
}

// Define trait implementation for MessageContent
impl MessageContent for KGRound2Message1 {
    fn validate_basic(&self) -> bool { self.validate() }
}


// Corresponds to KGRound2Message2 in Go protobuf
#[derive(Clone, PartialEq, Message)]
pub struct KGRound2Message2 {
    #[prost(bytes="vec", repeated, tag="1")]
    pub decommitment: Vec<Vec<u8>>, // Assuming HashDeCommitment bytes
    // Schnorr proof bytes (need concrete serialization for SchnorrProof)
    #[prost(bytes="vec", tag="2")]
    pub proof_bytes: Vec<u8>,
    // Removed separate proof fields
    // #[prost(bytes="vec", tag="2")] pub proof_alpha_x: Vec<u8>,
    // #[prost(bytes="vec", tag="3")] pub proof_alpha_y: Vec<u8>,
    // #[prost(bytes="vec", tag="4")] pub proof_t: Vec<u8>,
}

impl KGRound2Message2 {
    pub fn validate(&self) -> bool {
        !self.decommitment.is_empty() && self.decommitment.iter().all(|v| !v.is_empty()) &&
        !self.proof_bytes.is_empty()
    }

    // TODO: Update unmarshalling based on concrete types
    pub fn unmarshal_decommitment(&self) -> Result<HashDeCommitment, TssError> {
        // Assuming HashDeCommitment::from_bytes exists
        unimplemented!("unmarshal_decommitment needs concrete HashDeCommitment type");
        // Ok(HashDeCommitment::from_bytes(&self.decommitment)?)
    }

    pub fn unmarshal_zk_proof(&self) -> Result<SchnorrProof, TssError> {
        // Assuming SchnorrProof::from_bytes exists
        unimplemented!("unmarshal_zk_proof needs concrete SchnorrProof type");
        // Ok(SchnorrProof::from_bytes(&self.proof_bytes)?)
    }
}

// Define trait implementation for MessageContent
impl MessageContent for KGRound2Message2 {
    fn validate_basic(&self) -> bool { self.validate() }
}


// Removed KGRound3Message
// Removed KeyGenMessage enum
// Removed ParsedKeyGenMessage struct


// --- Message Creation Helpers --- //
// These helpers now return the message content struct directly.
// Wrapping into ParsedMessage/TssMessage should happen in the Party/Round logic.

pub fn new_kg_round1_message(
    commitment: &HashCommitment, // Use actual HashCommitment
) -> KGRound1Message {
    KGRound1Message {
        commitment: commitment.to_bytes(), // Assuming to_bytes() exists
    }
}

pub fn new_kg_round2_message1(
    share: &VssShare, // Use actual VssShare
) -> KGRound2Message1 {
    KGRound2Message1 {
        share: share.to_bytes(), // Assuming to_bytes() exists
    }
}

pub fn new_kg_round2_message2(
    decommitment: &HashDeCommitment,
    proof: &SchnorrProof,
) -> KGRound2Message2 {
    KGRound2Message2 {
        decommitment: decommitment.to_bytes(), // Assuming to_bytes() exists
        proof_bytes: proof.to_bytes(), // Assuming to_bytes() exists
    }
}

// Helper function to parse message content from payload bytes
// This assumes the payload IS the prost-encoded message content.
pub fn parse_message_from_payload<T: Message + Default>(payload: &[u8]) -> Result<T, prost::DecodeError> {
     T::decode(payload)
}


// Example of how LocalParty::store_message might use this:
/*
fn store_message(&mut self, msg: ParsedMessage) -> Result<(), TssError> {
    self.validate_message(&msg)?;
    let from_id = msg.from().clone();

    // Determine expected type based on round? Or try parsing?
    let current_round = self.base.current_round_number().unwrap_or(0);

    let mut temp_guard = self.temp.lock().unwrap();

    match current_round { // Simplified logic: assumes message belongs to current round
        1 => {
            let r1msg: KGRound1Message = parse_message_from_payload(&msg.wire_bytes)?;
            if r1msg.validate_basic() {
                temp_guard.round_1_messages.insert(from_id, r1msg);
            } else { return Err(TssError::InvalidMessage); }
        }
        2 => {
            // Need a way to distinguish R2M1 from R2M2 from wire_bytes
            // Maybe a type hint field in ParsedMessage/MessageRouting?
            // Or try parsing both?
            if let Ok(r2m1) = parse_message_from_payload::<KGRound2Message1>(&msg.wire_bytes) {
                 if r2m1.validate_basic() && !msg.is_broadcast() {
                     temp_guard.round_2_messages1.insert(from_id, r2m1);
                 } else { return Err(TssError::InvalidMessage); }
            } else if let Ok(r2m2) = parse_message_from_payload::<KGRound2Message2>(&msg.wire_bytes) {
                 if r2m2.validate_basic() && msg.is_broadcast() {
                     temp_guard.round_2_messages2.insert(from_id, r2m2);
                 } else { return Err(TssError::InvalidMessage); }
            } else {
                 return Err(TssError::InvalidMessage); // Couldn't parse as R2M1 or R2M2
            }
        }
        _ => return Err(TssError::UnexpectedMessageReceived), // No messages expected later
    }
    self.base.store_raw_message(msg)?; // Let BaseParty track received status
    Ok(())
}
*/
