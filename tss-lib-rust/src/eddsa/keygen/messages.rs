// EDDSA Keygen protocol messages (ported from eddsa-keygen.pb.go)
// Use prost for protobuf compatibility and serde for serialization

use prost::Message;
use serde::{Serialize, Deserialize};
use crate::tss::party_id::PartyID; // Assuming this exists
use crate::eddsa::keygen::save_data::{EdDSAPublicKeyPoint}; // Import other types if needed
use crate::crypto::paillier; // Import actual paillier module
use num_bigint::BigInt;
use crate::crypto::commitments::hash_commit_decommit::Decommitment;
use crate::crypto::dln_proof::Proof as DLNProof;
use crate::crypto::paillier::{PaillierProof, PublicKey as PaillierPublicKey}; // Use actual PublicKey, keep PaillierProof placeholder
use crate::eddsa::keygen::LocalPartySaveData;
use crate::tss::error::TssError; // Use actual TssError
use crate::tss::message::{TssMessage, TssMessageRouting}; // Use actual TssMessage
use crate::tss::party_id::{PartyID, SortedPartyIDs}; // Use actual PartyID/SortedPartyIDs
use crate::vss::VSSShare; // Keep VSSShare placeholder
use std::error::Error;

// --- Placeholders for Crypto Primitives/Proofs --- //
// TODO: Replace with actual types from the library/crates

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashCommitment(pub Vec<u8>); // Placeholder

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashDeCommitment(pub Vec<Vec<u8>>); // Placeholder for Vec<*big.Int>

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlnProof(pub Vec<u8>); // Placeholder

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssShare(pub BigInt); // Placeholder for *vss.Share

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacProof(pub Vec<u8>); // Placeholder for *facproof.ProofFac

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModProof(pub Vec<u8>); // Placeholder for *modproof.ProofMod

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierProof(pub Vec<u8>); // Placeholder for paillier.Proof (which is [][]byte in Go)

// --- End Placeholders --- //

// Use actual paillier::PublicKey
#[derive(Debug, Clone /* Serialize, Deserialize */)] // PK might not be serializable directly
pub struct KGRound1Message {
    pub commitment: HashCommitment,     // Commitment C_i
    pub paillier_pk: paillier::PublicKey, // Paillier PK_i
    pub n_tilde: BigInt,              // N-tilde_i
    pub h1: BigInt,
    pub h2: BigInt,
    pub dln_proof_1: DlnProof,         // DLNProof (N_tilde_i, h1_i)
    pub dln_proof_2: DlnProof,         // DLNProof (N_tilde_i, h2_i)
}

impl KGRound1Message {
    // Basic validation (presence of data)
    pub fn validate_basic(&self) -> bool {
        !self.commitment.0.is_empty() &&
        // Check n in paillier_pk is non-zero? Depends on PublicKey struct
        // self.paillier_pk.n != BigInt::zero() &&
        !self.n_tilde.to_bytes_be().1.is_empty() &&
        !self.h1.to_bytes_be().1.is_empty() &&
        !self.h2.to_bytes_be().1.is_empty() &&
        !self.dln_proof_1.0.is_empty() &&
        !self.dln_proof_2.0.is_empty()
        // TODO: Add length checks for proofs if known
    }

    // TODO: Implement constructor `new` similar to Go if needed
    // TODO: Implement unmarshalling methods if direct access isn't sufficient
    // (e.g., `unmarshal_dln_proof_1` -> Result<ActualDlnProofType, Error>)
}

// Corresponds to KGRound2Message1 in Go
// P2P message sending VSS share and Factorization proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KGRound2Message1 {
    pub share: VssShare,       // VSS Share V_ij
    pub fac_proof: Option<FacProof>, // Factorization proof (optional in Go for backward compatibility)
}

impl KGRound2Message1 {
    pub fn validate_basic(&self) -> bool {
        // Check share presence
        !self.share.0.to_bytes_be().1.is_empty() &&
        // Check proof presence if it exists (optional)
        self.fac_proof.as_ref().map_or(true, |p| !p.0.is_empty())
        // TODO: Add specific checks for share/proof validity
    }
     // TODO: Implement constructor `new` similar to Go if needed
     // TODO: Implement unmarshalling methods if needed
}

// Corresponds to KGRound2Message2 in Go
// Broadcasts decommitment and Modulo proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KGRound2Message2 {
    pub decommitment: HashDeCommitment, // Decommitment D_i
    pub mod_proof: Option<ModProof>,     // Modulo proof (optional in Go for backward compatibility)
}

impl KGRound2Message2 {
    pub fn validate_basic(&self) -> bool {
        !self.decommitment.0.is_empty() && self.decommitment.0.iter().all(|v| !v.is_empty()) &&
        self.mod_proof.as_ref().map_or(true, |p| !p.0.is_empty())
        // TODO: Add specific checks for decommitment/proof validity
    }
     // TODO: Implement constructor `new` similar to Go if needed
     // TODO: Implement unmarshalling methods if needed
}

// Corresponds to KGRound3Message in Go
// Broadcasts Paillier encryption proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KGRound3Message {
    pub paillier_proof: PaillierProof, // Paillier encryption proof
}

impl KGRound3Message {
    pub fn validate_basic(&self) -> bool {
        !self.paillier_proof.0.is_empty()
        // TODO: Add specific checks for proof validity
    }
     // TODO: Implement constructor `new` similar to Go if needed
     // TODO: Implement unmarshalling methods if needed
}

// TODO: Consider if Round 4 message is needed for EdDSA or if the protocol differs.
// If needed, define KGRound4Message struct based on ECDSA version or EdDSA spec.

// --- KeyGenMessage --- //

// NOTE: Actual message wrapper will come from crate::tss::message::TssMessage
// We define KeyGenMessage here as the *content* of TssMessage for the keygen protocol.
#[derive(Debug, Clone, Serialize, Deserialize)] // Add necessary derives
#[allow(clippy::large_enum_variant)]
pub enum KeyGenMessage {
    Round1(KGRound1Message),
    Round2Message1(KGRound2Message1),
    Round2Message2(KGRound2Message2),
    Round3(KGRound3Message),
}

impl KeyGenMessage {
    pub fn get_type(&self) -> String {
        match self {
            KeyGenMessage::Round1(_) => "KeyGenRound1Message".to_string(),
            KeyGenMessage::Round2Message1(_) => "KeyGenRound2Message1".to_string(),
            KeyGenMessage::Round2Message2(_) => "KeyGenRound2Message2".to_string(),
            KeyGenMessage::Round3(_) => "KeyGenRound3Message".to_string(),
        }
    }
}

// --- ParsedKeyGenMessage --- //
// This struct wraps the KeyGenMessage content along with the common TssMessage fields
// It is used *after* a TssMessage has been received and parsed.
#[derive(Debug, Clone)]
pub struct ParsedKeyGenMessage {
    pub header: TssMessageRouting, // Use actual header type
    pub message: KeyGenMessage,
}

impl ParsedKeyGenMessage {
    // Creates a new ParsedKeyGenMessage from a generic TssMessage.
    // Assumes the TssMessage has already been validated to be for the KeyGen protocol.
    pub fn from_tss_message(msg: TssMessage) -> Result<Self, TssError> {
        let keygen_msg: KeyGenMessage = serde_json::from_slice(&msg.body).map_err(|e| {
            TssError::SerializationError { // Use actual TssError variant
                reason: format!("Failed to deserialize KeyGenMessage body: {}", e),
            }
        })?;

        Ok(ParsedKeyGenMessage {
            header: msg.routing,
            message: keygen_msg,
        })
    }

    // Helper methods to access header fields directly
    pub fn sender_id(&self) -> &PartyID {
        &self.header.from
    }

    pub fn is_broadcast(&self) -> bool {
        self.header.is_broadcast
    }
}

// --- Message Creation Helpers --- //

pub fn new_kg_round1_message(
    from_id: &PartyID, // Use actual PartyID
    commitment: Decommitment<ECPoint>,
    paillier_pk: &PaillierPublicKey, // Use actual Paillier PK
    n_tilde: &BigInt,
    h1: &BigInt,
    h2: &BigInt,
    dln_proof_1: &DLNProof,
    dln_proof_2: &DLNProof,
) -> Result<TssMessage, TssError> { // Return actual TssMessage
    let body = KeyGenMessage::Round1(KGRound1Message {
        commitment,
        paillier_pk: paillier_pk.clone(), // Clone the actual public key
        n_tilde: n_tilde.clone(),
        h1: h1.clone(),
        h2: h2.clone(),
        dln_proof_1: dln_proof_1.clone(),
        dln_proof_2: dln_proof_2.clone(),
    });
    TssMessage::new_broadcast(from_id.clone(), "keygen".to_string(), body)
}

pub fn new_kg_round2_message1(
    from_id: &PartyID, // Use actual PartyID
    to_id: &PartyID,   // Use actual PartyID
    share: VSSShare,  // Keep VSSShare placeholder
) -> Result<TssMessage, TssError> { // Return actual TssMessage
    let body = KeyGenMessage::Round2Message1(KGRound2Message1 { share });
    TssMessage::new_ptp(from_id.clone(), to_id.clone(), "keygen".to_string(), body)
}

pub fn new_kg_round2_message2(
    from_id: &PartyID, // Use actual PartyID
    decommitment: Decommitment<ECPoint>,
    proof: DLNProof, // Placeholder for the actual DLN proof type
) -> Result<TssMessage, TssError> { // Return actual TssMessage
    let body = KeyGenMessage::Round2Message2(KGRound2Message2 {
        decommitment,
        proof, // Placeholder DLNProof
    });
    TssMessage::new_broadcast(from_id.clone(), "keygen".to_string(), body)
}

pub fn new_kg_round3_message(
    from_id: &PartyID,    // Use actual PartyID
    paillier_proof: PaillierProof, // Keep placeholder proof type
) -> Result<TssMessage, TssError> { // Return actual TssMessage
    let body = KeyGenMessage::Round3(KGRound3Message {
        paillier_proof, // Placeholder proof
    });
    TssMessage::new_broadcast(from_id.clone(), "keygen".to_string(), body)
}
