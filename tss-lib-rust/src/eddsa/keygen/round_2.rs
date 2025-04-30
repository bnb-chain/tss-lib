// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// EDDSA Keygen round 2 logic (ported from Go)

use std::sync::{Arc, Mutex, mpsc::Sender};
use prost::Message;
use num_bigint::BigInt;
use rand::rngs::OsRng;

// Keygen specific imports
use crate::eddsa::keygen::Parameters;
use crate::eddsa::keygen::BaseParty;
use crate::eddsa::keygen::TssError;
use crate::eddsa::keygen::rounds::KeygenRound;
use crate::eddsa::keygen::round_3::Round3;
use crate::eddsa::keygen::messages::{KGRound1Message, KGRound2Message1, KGRound2Message2, SchnorrProofPlaceholder, PointPlaceholder};
use crate::eddsa::keygen::local_party::{KeygenPartyTempData, KeygenPartySaveData};

// TSS core imports
use crate::tss::party_id::PartyID;
use crate::tss::message::ParsedMessage;
use crate::tss::message::MessageContent; // Needed for store_message validation

// Crypto imports
use crate::crypto::vss::{ShareVec as Vs, Share as IndividualVssShare};

// Other necessary imports
use std::fmt::Debug;

// Remove placeholder mods for facproof and modproof
/*
mod facproof { ... }
mod modproof { ... }
*/

// Add placeholder for Schnorr proof generation
mod schnorr {
    use super::{BigInt, Error, SchnorrProof, PartyID, CurvePoint, Scalar};
    use rand::RngCore;
    // TODO: Replace CurvePoint and Scalar with actual types
    type CurvePoint = Vec<u8>; 
    type Scalar = BigInt;

    pub fn new_zk_proof(
        _context: &[u8],
        _secret: &Scalar,
        _public_commitment: &CurvePoint, // Use actual Point type
        _rng: &mut dyn RngCore,
    ) -> Result<SchnorrProof, Box<dyn Error>> {
        println!("Warning: Using placeholder schnorr::new_zk_proof");
        Ok(SchnorrProof { /* dummy fields */ alpha_bytes: vec![1], t_bytes: vec![2] })
    }
}

// ... CurveParams placeholder remains ...

// Helper to construct KGRound2Message1 (P2P) - Corrected
fn new_kg_round2_message1(
    to: &PartyID,
    from: &PartyID,
    share: &VssShare, // Use actual VssShare type
) -> Result<Message, Box<dyn Error>> { // Removed FacProof
    let content = KeygenMessageEnum::Round2_1(KGRound2Message1 {
        share: share.clone(),
        // Removed fac_proof field
    });
    // TODO: Implement actual wire byte serialization
    let mut wire_bytes = Vec::new();
    content.encode(&mut wire_bytes)?; // Assuming prost encoding

    Ok(Message {
        content_type: PROTOCOL_NAME.to_string(),
        wire_bytes,
        from: from.clone(),
        to: Some(vec![to.clone()]), // Specify recipient
        is_broadcast: false,
    })
}

// Helper to construct KGRound2Message2 (Broadcast) - Corrected
fn new_kg_round2_message2(
    from: &PartyID,
    decommitment: &HashDeCommitment,
    schnorr_proof: SchnorrProof, // Added SchnorrProof
) -> Result<Message, Box<dyn Error>> { // Removed ModProof
    let content = KeygenMessageEnum::Round2_2(KGRound2Message2 {
        decommitment: decommitment.clone(),
        schnorr_proof, // Include Schnorr proof
        // Removed mod_proof field
    });
    // TODO: Implement actual wire byte serialization
    let mut wire_bytes = Vec::new();
    content.encode(&mut wire_bytes)?; // Assuming prost encoding

    Ok(Message {
        content_type: PROTOCOL_NAME.to_string(),
        wire_bytes,
        from: from.clone(),
        is_broadcast: true,
    })
}

// --- End Placeholder Crypto Operations/Types --- //

#[derive(Debug)]
pub struct Round2 {
    base: BaseParty, // Use keygen::BaseParty
    // Remove direct Arcs
}

impl Round2 {
    pub fn new(
        params: Arc<Parameters>,
        save_data: Arc<Mutex<KeygenPartySaveData>>,
        temp_data: Arc<Mutex<KeygenPartyTempData>>,
        out_channel: Sender<TssMessage>,
        end_channel: Sender<KeygenPartySaveData>,
    ) -> Box<dyn TssRound> {
        // Create BaseParty instance
        let base = BaseParty::new(params, temp_data, save_data, out_channel, 2)
            .with_end_channel(end_channel);

        Box::new(Self { base })
    }

    // Remove helper methods - use self.base helpers instead
}

// Implement the new KeygenRound trait
impl KeygenRound for Round2 {
    fn round_number(&self) -> u32 { self.base.round_number }

    fn base(&self) -> &BaseParty { &self.base }
    fn base_mut(&mut self) -> &mut BaseParty { &mut self.base }

    fn start(&mut self) -> Result<(), TssError> {
        if self.base.started {
            return Err(self.base.wrap_base_error("Round 2 already started".to_string()));
        }
        self.base.started = true;
        self.base.reset_ok();

        let party_id = self.base.party_id().clone();
        let i = self.base.party_index();
        let party_count = self.base.party_count();
        let mut rng = OsRng;
        let mut temp_guard = self.base.temp();

        // 1. Store Round 1 Commitments (KGCs)
        temp_guard.kgcs = vec![None; party_count];
        for (j_id, r1_msg) in &temp_guard.round_1_messages { // Iterate map directly
             let j = j_id.index();
             temp_guard.kgcs[j] = Some(r1_msg.unmarshal_commitment());
        }
        println!("Round 2: Stored Round 1 commitments.");

        // 2. P2P send share ij to Pj
        let shares = temp_guard.shares.clone().ok_or_else(|| {
            TssError::InternalError { message: "Missing VSS shares in temp data".to_string() }
        })?;

        for (j, pj) in self.base.params().parties().iter().enumerate() {
            let share_ij = &shares[j]; // Assuming Vec<IndividualVssShare>
            // TODO: Need IndividualVssShare::to_bytes()
            let share_bytes = vec![]; // Placeholder
            let msg_content = KGRound2Message1 { share: share_bytes };
            let msg_payload = msg_content.encode_to_vec();

            if j == i {
                 self.base.set_ok(i)?;
                 temp_guard.round_2_messages1.insert(party_id.clone(), msg_content);
            } else {
                 let p2p_msg = self.base.new_p2p_message(pj, msg_payload)?;
                 self.base.send_p2p(p2p_msg)?;
            }
        }
        println!("Round 2: Sent P2P shares.");

        // 3. Compute Schnorr prove pi_i = ZKProof{ui}(vs_i[0])
        let context_i = [temp_guard.ssid.as_ref().unwrap().as_slice(), BigInt::from(i).to_bytes_be().1.as_slice()].concat();
        let ui_bigint = temp_guard.ui.as_ref().ok_or_else(|| {
             TssError::InternalError { message: "Missing secret ui in temp data".to_string() }
        })?;
        let vsi0_point = temp_guard.vs.as_ref().unwrap()[0].clone();

        // TODO: Implement Schnorr proof generation
        let schnorr_proof = SchnorrProofPlaceholder{ alpha: PointPlaceholder { x: vec![], y: vec![] }, t: vec![]};

        // 4. BROADCAST de-commitments and Schnorr proof
        let decommitment_vec = temp_guard.de_commit_poly_g.clone().ok_or_else(|| {
             TssError::InternalError { message: "Missing VSS decommitment in temp data".to_string() }
        })?;
        let decommitment_bytes: Vec<Vec<u8>> = decommitment_vec.iter().map(|d| d.to_bytes_be().1).collect();
        let msg_content = KGRound2Message2 {
            decommitment: decommitment_bytes,
            proof_alpha_x: schnorr_proof.alpha.x,
            proof_alpha_y: schnorr_proof.alpha.y,
            proof_t: schnorr_proof.t,
        };
        let msg_payload = msg_content.encode_to_vec();

        let broadcast_msg = self.base.new_broadcast_message(msg_payload)?;
        self.base.send_broadcast(broadcast_msg)?;

        // Mark self as OK for broadcast message type as well?
        // Assuming Round 2 needs two messages: one P2P share, one broadcast decommit.
        // BaseParty::ok only tracks one message per party. Refactor needed for multi-message rounds.
        // For now, let start() mark self OK for P2P message, and assume broadcast implicitly handled.

        println!("Round 2: Broadcasted decommitment and Schnorr proof.");

        Ok(())
    }

    fn store_message(&mut self, msg: ParsedMessage) -> Result<(), TssError> {
        let sender_index = self.base.params().parties().find_by_id(msg.from())
            .ok_or_else(|| TssError::PartyIndexNotFound)?;

        let content = msg.content();
        if content.downcast_ref::<KGRound2Message1>().is_none() &&
           content.downcast_ref::<KGRound2Message2>().is_none() {
            return Err(TssError::BaseError {
                message: format!("Unexpected message type stored for Round 2: {:?}", content)
            });
        }
        self.base.set_ok(sender_index)?;
        Ok(())
    }

    fn can_proceed(&self) -> bool {
        // TODO: This check is inaccurate for rounds needing multiple message types per party.
        // BaseParty::message_count only tracks one message type.
        // Needs refactoring based on how BaseParty stores messages or use temp maps.
        let party_count = self.base.party_count();
        // Temporary check using local maps
        let temp_guard = self.base.temp();
        temp_guard.round_2_messages1.len() == party_count && temp_guard.round_2_messages2.len() == party_count
    }

    fn proceed(&mut self) -> Result<(), TssError> {
        if !self.can_proceed() {
            return Err(TssError::ProceedCalledWhenNotReady);
        }
        println!("Round 2 can proceed.");
        Ok(())
    }

    // Implement next_round using BaseParty fields
    fn next_round(self: Box<Self>) -> Option<Box<dyn KeygenRound>> {
        Some(Round3::new(
            self.base.params.clone(),
            self.base.save_data.clone(),
            self.base.temp_data.clone(),
            self.base.out_channel.clone(),
            self.base.end_channel.clone().expect("End channel should be set for round 2"),
        ))
    }
}

// Placeholder for ParsedMessage until refactoring
#[derive(Debug, Clone)]
pub struct ParsedMessage { pub dummy: u8, pub from_party: Option<PartyID> } // Added from for store_message temp fix
