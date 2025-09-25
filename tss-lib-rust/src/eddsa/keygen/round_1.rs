// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// EDDSA Keygen round 1 logic (ported from Go)

// Removed unused get_ssid import
// use crate::eddsa::keygen::rounds::{Round, RoundCtx, RoundState, get_ssid};
use crate::eddsa::keygen::save_data::{LocalPartySaveData, LocalPreParams};
use crate::eddsa::keygen::local_party::{LocalTempData, Message, ParsedMessage, TssError, PartyID, Parameters, KeygenMessageEnum, Vs, Shares, KeygenPartyTempData, KeygenPartySaveData};
use crate::eddsa::keygen::messages::{KGRound1Message, HashCommitment, DlnProof, VssShare, HashDeCommitment};
use num_bigint::{BigInt, RandBigInt};
use num_traits::{Zero};
use rand::rngs::OsRng; // Use a secure RNG
use std::sync::mpsc::Sender;
use std::error::Error;
use crate::eddsa::keygen::round_2::Round2; // Import Round2 for next_round
use crate::crypto::paillier; // Import actual paillier
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::tss::{error::TssError, message::TssMessage};
use crate::eddsa::keygen::{KeygenRound, PROTOCOL_NAME};
use crate::tss::curve::{CurveName, get_curve_params, CurveParams};
use crate::crypto::hashing::hash_bytes;
use crate::tss::{error::TssError, message::{TssMessage, ParsedMessage}, party::{Party as TssParty, Round as TssRound, BaseParty}, party_id::PartyID};
use crate::crypto::vss::{ShareVec as Vs, Share as IndividualVssShare}; // Assuming Vs is type alias for Vec<Point> or similar
use crate::crypto::commitments::HashCommitDecommit;
use crate::eddsa::keygen::rounds::get_ssid;
use crate::eddsa::keygen::BaseParty; // Import keygen::BaseParty
use prost::Message; // For encode_to_vec
use crate::eddsa::keygen::party_base::TssMessage; // Use placeholder TssMessage
use crate::tss::message::ParsedMessage; // Use tss::ParsedMessage
use crate::eddsa::keygen::TssError; // Import keygen::TssError
use crate::eddsa::keygen::rounds::KeygenRound; // Import the new trait
use std::fmt::Debug; // For KeygenRound trait bound

// --- Placeholder Crypto Operations --- //
// TODO: Replace with actual implementations from crates

mod common {
    use super::{BigInt, CurveParams, EdDSAPublicKeyPoint, RandBigInt};
    use num_traits::Zero;
    use rand::RngCore;
    pub fn get_random_positive_int(rng: &mut dyn RngCore, upper_bound: &BigInt) -> BigInt {
        // Simplified placeholder
        rng.gen_bigint_range(&BigInt::from(1), upper_bound)
    }
}

mod vss {
    use super::{BigInt, CurveParams, ed25519_dalek::EdwardsPoint, Error, Parameters, PartyID, Vs, IndividualVssShare};
    use rand::RngCore;

    pub fn create(
        _ec_params: &CurveParams,
        _threshold: usize,
        secret: BigInt,
        party_keys: &[BigInt],
        _rng: &mut dyn RngCore,
    ) -> Result<(Vec<EdwardsPoint>, Vec<IndividualVssShare>), Box<dyn Error>> {
        println!("Warning: Using placeholder vss::create");
        let commitments = vec![ed25519_dalek::constants::ED25519_BASEPOINT_POINT; _threshold + 1];
        let shares = party_keys.iter().enumerate().map(|(idx, _key)| {
             IndividualVssShare { scalar: ed25519_dalek::Scalar::zero() }
         }).collect();
        Ok((commitments, shares))
    }
}

mod crypto {
    use super::{ed25519_dalek::EdwardsPoint, Error};
    pub fn flatten_ec_points(_points: &Vec<EdwardsPoint>) -> Result<Vec<u8>, Box<dyn Error>> {
        println!("Warning: Using placeholder crypto::flatten_ec_points");
        Ok(_points.iter().flat_map(|p| p.compress().to_bytes()).collect())
    }
}

// TODO: Replace with actual EC Curve parameters for EdDSA (e.g., Ed25519)
pub struct CurveParams { pub p: BigInt, pub n: BigInt, pub gx: BigInt, pub gy: BigInt }
impl CurveParams { pub fn get() -> Self { CurveParams { p: BigInt::zero(), n: BigInt::from(100), gx: BigInt::zero(), gy: BigInt::zero() } } } // Dummy data

// Helper to construct the broadcast message (Simplified)
fn new_kg_round1_message(
    from: &PartyID,
    commitment: HashCommitment,
) -> Result<Message, Box<dyn Error>> { // Removed paillier/DLN args
    let content = KeygenMessageEnum::Round1(KGRound1Message {
        commitment, // Only include commitment
        // Remove paillier_pk, n_tilde, h1, h2, dln_proof_1, dln_proof_2
    });

    // TODO: Implement actual wire byte serialization for the simplified KGRound1Message
    let mut wire_bytes = Vec::new();
    content.encode(&mut wire_bytes)?; // Assuming prost encoding

    Ok(Message {
        content_type: PROTOCOL_NAME.to_string(), // Use PROTOCOL_NAME
        wire_bytes,
        from: from.clone(),
        is_broadcast: true,
    })
}

// --- End Placeholder Crypto Operations --- //

#[derive(Debug)]
pub struct Round1 {
    base: BaseParty,
}

impl Round1 {
    pub fn new(
        params: Arc<Parameters>,
        save_data: Arc<Mutex<KeygenPartySaveData>>,
        temp_data: Arc<Mutex<KeygenPartyTempData>>,
        out_channel: Sender<TssMessage>,
        end_channel: Sender<KeygenPartySaveData>, // Keep end_channel in signature for LocalParty
    ) -> Box<dyn TssRound> {
        // Create BaseParty instance
        let base = BaseParty::new(params, temp_data, save_data, out_channel, 1)
            .with_end_channel(end_channel); // Add end channel

        Box::new(Self { base })
    }

    // Removed public methods now part of trait
    /*
    pub fn round_number(&self) -> u32 { ... }
    pub fn params(&self) -> &Arc<Parameters> { ... }
    pub fn start(&mut self) -> Result<(), TssError> { ... }
    pub fn store_message(&mut self, msg: ParsedMessage) -> Result<(), TssError> { ... }
    pub fn can_proceed(&self) -> bool { ... }
    pub fn proceed(&mut self) -> Result<(), TssError> { ... }
    */
}

// Implement the new KeygenRound trait
impl KeygenRound for Round1 {
    fn round_number(&self) -> u32 { self.base.round_number }

    fn base(&self) -> &BaseParty { &self.base }
    fn base_mut(&mut self) -> &mut BaseParty { &mut self.base }

    fn start(&mut self) -> Result<(), TssError> {
        if self.base.started {
            return Err(self.base.wrap_base_error("Round 1 already started".to_string()));
        }
        self.base.started = true;
        self.base.reset_ok();

        let mut rng = OsRng;
        let curve_params = get_curve_params(self.base.params().curve())
            .ok_or_else(|| TssError::CurveNotFoundError)?;
        let curve_order = match curve_params {
             CurveParams::Ed25519 { order, .. } => order,
             _ => return Err(TssError::UnsupportedCurveError),
        };

        let party_id = self.base.party_id().clone();
        let i = self.base.party_index();
        let mut temp_guard = self.base.temp();
        let mut save_guard = self.base.save();

        save_guard.started = true;
        temp_guard.ssid_nonce = Some(BigInt::zero());
        let ssid = get_ssid(self.base.params(), 1, &temp_guard.ssid_nonce.as_ref().unwrap())?;
        temp_guard.ssid = Some(ssid);

        let ui_bigint = rng.gen_bigint_range(&BigInt::one(), curve_order);
        temp_guard.ui = Some(ui_bigint.clone());

        let party_keys_bigint: Vec<&BigInt> = self.base.params().parties().iter().map(|p| p.key()).collect();
        let threshold = self.base.params().threshold();

        let (vs, shares) = vss::create(&curve_params, threshold, ui_bigint.clone(), &party_keys_bigint, &mut rng)
            .map_err(|e| TssError::KeygenVssError{ source_error: e.to_string() })?;

        save_guard.ks = party_keys_bigint.into_iter().cloned().map(Some).collect();
        temp_guard.vs = Some(vs.clone());
        temp_guard.shares = Some(shares.clone());

        if let Some(key) = self.base.params().parties().get(i).map(|p| p.key().clone()) {
             save_guard.share_id = Some(key);
        } else {
             return Err(TssError::InternalError { message: format!("Party index {} out of bounds", i) });
        }

        let vs_points_bytes: Vec<u8> = crypto::flatten_ec_points(&vs)
             .map_err(|e| TssError::InternalError { message: format!("Failed to flatten points: {}", e)})?;
        let ui_bytes = temp_guard.ui.as_ref().unwrap().to_bytes_be().1;
        let commit_decommit = HashCommitDecommit::new_with_randomness(
            rng.gen_bigint(256),
            &[&ui_bytes, &vs_points_bytes].iter().map(|b| BigInt::from_bytes_be(num_bigint::Sign::Plus, b)).collect::<Vec<_>>(),
        );
        let cmt_c = commit_decommit.c.clone();
        let cmt_d = commit_decommit.d.clone();
        temp_guard.de_commit_poly_g = Some(cmt_d);

        let msg_content = KGRound1Message { commitment: cmt_c.to_bytes_be().1 };
        let msg_payload = msg_content.encode_to_vec();

        let broadcast_msg = self.base.new_broadcast_message(msg_payload)?;
        self.base.send_broadcast(broadcast_msg)?;

        self.base.set_ok(i)?;

        Ok(())
    }

    fn store_message(&mut self, msg: ParsedMessage) -> Result<(), TssError> {
        let sender_index = self.base.params().parties().find_by_id(msg.from())
            .ok_or_else(|| TssError::PartyIndexNotFound)?;

        if msg.content().downcast_ref::<KGRound1Message>().is_none() {
            return Err(TssError::BaseError{
                 message: format!("Unexpected message type stored for Round 1: {:?}", msg.content())
            });
        }
        self.base.set_ok(sender_index)?;
        Ok(())
    }

    fn can_proceed(&self) -> bool {
        self.base.message_count() == self.base.party_count()
    }

    fn proceed(&mut self) -> Result<(), TssError> {
        if !self.can_proceed() {
            return Err(TssError::ProceedCalledWhenNotReady);
        }
        Ok(())
    }

    // Implement next_round using BaseParty fields
    fn next_round(self: Box<Self>) -> Option<Box<dyn KeygenRound>> {
        Some(Round2::new(
            self.base.params.clone(),
            self.base.save_data.clone(),
            self.base.temp_data.clone(),
            self.base.out_channel.clone(),
            self.base.end_channel.clone().expect("End channel should be set for round 1"),
        ))
    }
}

// Placeholder for ParsedMessage until refactoring
#[derive(Debug, Clone)]
pub struct ParsedMessage { pub dummy: u8, pub from_party: Option<PartyID> } // Added from for store_message temp fix
impl ParsedMessage {
    pub fn from(&self) -> &PartyID {
        self.from_party.as_ref().expect("ParsedMessage missing from party")
    }
}
