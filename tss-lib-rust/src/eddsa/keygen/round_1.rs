// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// EDDSA Keygen round 1 logic (ported from Go)

use crate::eddsa::keygen::rounds::{Round, RoundCtx, RoundState, get_ssid};
use crate::eddsa::keygen::save_data::{LocalPartySaveData, LocalPreParams};
use crate::eddsa::keygen::local_party::{LocalTempData, Message, ParsedMessage, TssError, PartyID, Parameters, KeygenMessageEnum, Vs, Shares};
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
    use super::{BigInt, CurveParams, EdDSAPublicKeyPoint, Error, Parameters, PartyID, Vs, Shares, VssShare};
    use rand::RngCore;

    pub fn create(
        _ec_params: &CurveParams,
        _threshold: usize,
        secret: BigInt,
        party_ids: &[PartyID],
        _rng: &mut dyn RngCore,
    ) -> Result<(Vs, Shares), Box<dyn Error>> {
        println!("Warning: Using placeholder vss::create");
        let point = EdDSAPublicKeyPoint { point: vec![1] }; // Dummy point
        let commitments = Vs(vec![point; _threshold + 1]); // Dummy commitments
        let shares = Shares(
            party_ids.iter().map(|p| VssShare(secret.clone() + BigInt::from(p.index)) ) // Dummy shares
            .collect()
        );
        Ok((commitments, shares))
    }
}

mod crypto {
    use super::{EdDSAPublicKeyPoint, Error};
    pub fn flatten_ec_points(_points: &Vec<EdDSAPublicKeyPoint>) -> Result<Vec<u8>, Box<dyn Error>> {
        println!("Warning: Using placeholder crypto::flatten_ec_points");
        Ok(vec![1,2,3]) // Dummy flat bytes
    }
}

mod commitments {
    use super::{BigInt, HashCommitment, HashDeCommitment};
    use rand::RngCore;
    pub fn new_hash_commitment(_rng: &mut dyn RngCore, data: &[u8]) -> (HashCommitment, HashDeCommitment) {
        println!("Warning: Using placeholder commitments::new_hash_commitment");
        let commitment = HashCommitment(data.to_vec()); // Dummy commitment (just the data)
        let decommitment = HashDeCommitment(vec![data.to_vec()]); // Dummy decommitment
        (commitment, decommitment)
    }
}

mod dlnproof {
    use super::{BigInt, DlnProof};
    use rand::RngCore;
    pub fn new(_h1: &BigInt, _h2: &BigInt, _alpha: &BigInt, _p: &BigInt, _q: &BigInt, _n_tilde: &BigInt, _rng: &mut dyn RngCore) -> DlnProof {
        println!("Warning: Using placeholder dlnproof::new");
        DlnProof(vec![1,2,3]) // Dummy proof bytes
    }
}

// TODO: Replace with actual EC Curve parameters for EdDSA (e.g., Ed25519)
pub struct CurveParams { pub p: BigInt, pub n: BigInt, pub gx: BigInt, pub gy: BigInt }
impl CurveParams { pub fn get() -> Self { CurveParams { p: BigInt::zero(), n: BigInt::from(100), gx: BigInt::zero(), gy: BigInt::zero() } } } // Dummy data

// Helper to construct the broadcast message
fn new_kg_round1_message(
    from: &PartyID,
    commitment: HashCommitment,
    paillier_pk: &paillier::PublicKey,
    n_tilde: &BigInt,
    h1: &BigInt,
    h2: &BigInt,
    dln_proof_1: DlnProof,
    dln_proof_2: DlnProof,
) -> Result<Message, Box<dyn Error>> {
    let content = KeygenMessageEnum::Round1(KGRound1Message {
        commitment,
        paillier_pk: paillier_pk.clone(),
        n_tilde: n_tilde.clone(),
        h1: h1.clone(),
        h2: h2.clone(),
        dln_proof_1,
        dln_proof_2,
    });

    // TODO: Implement actual wire byte serialization for KGRound1Message
    // Need to handle serialization of paillier::PublicKey (e.g., its 'n' field)
    let wire_bytes = vec![0x01]; // Placeholder serialization

    Ok(Message {
        content_type: TASK_NAME.to_string(),
        wire_bytes,
        from: from.clone(),
        is_broadcast: true,
    })
}

// --- End Placeholder Crypto Operations --- //

#[derive(Debug)]
pub struct Round1 {
    params: Arc<Parameters>,
    temp_data: Arc<Mutex<KeygenPartyTmpData>>,
    save_data: Arc<Mutex<KeyGenPartySaveData>>,
    out_channel: Arc<Sender<TssMessage>>,
    end_channel: Arc<Sender<KeyGenPartySaveData>>,
    // Internal state for this round
    started: bool,
    messages_received: HashMap<PartyID, KGRound1Message>,
}

impl Round1 {
    pub fn new(
        params: Arc<Parameters>,
        save_data: Arc<Mutex<KeyGenPartySaveData>>,
        temp_data: Arc<Mutex<KeygenPartyTmpData>>,
        out_channel: Arc<Sender<TssMessage>>,
        end_channel: Arc<Sender<KeyGenPartySaveData>>,
    ) -> Box<dyn TssRound> {
        Box::new(Self {
            params,
            temp_data,
            save_data,
            out_channel,
            end_channel,
            started: false,
            messages_received: HashMap::new(),
        })
    }
}

impl KeygenRound for Round1 {
    fn temp(&self) -> Arc<Mutex<KeygenPartyTmpData>> {
        self.temp_data.clone()
    }
    fn data(&self) -> Arc<Mutex<KeyGenPartySaveData>> {
        self.save_data.clone()
    }
}

impl TssRound for Round1 {
    fn round_number(&self) -> u32 { 1 }

    fn params(&self) -> &Parameters { &self.params }

    fn start(&self) -> Result<(), TssError> {
        if self.started {
            return Err(self.wrap_keygen_error("Round 1 already started".into(), vec![]));
        }
        // Mark started? Need mutable access. Let's assume BaseParty handles this coordination
        // or we handle it internally when `proceed` is called.

        let mut rng = OsRng;
        // Get actual curve parameters for Ed25519
        let curve_params = get_curve_params(CurveName::Ed25519)
            .ok_or_else(|| self.wrap_keygen_error("Ed25519 curve parameters not found".into(), vec![]))?;

        // Extract order from the specific enum variant
        let curve_order = match &curve_params {
             CurveParams::Ed25519 { order, .. } => order,
             _ => return Err(self.wrap_keygen_error("Incorrect curve parameters received (expected Ed25519)".into(), vec![])),
        };

        let party_id = self.params.party_id();
        let i = self.params.party_index(); // Get index from Parameters

        // Lock data stores
        let mut temp_guard = self.temp_data.lock().unwrap();
        let mut data_guard = self.save_data.lock().unwrap();

        // Mark the party data as started
        data_guard.started = true;

        // 1. Calculate "partial" key share ui
        let ui = rng.gen_bigint_range(&BigInt::one(), curve_order);
        temp_guard.ui = Some(ui.clone()); // Store for tests/debug

        // 2. Compute the VSS shares
        let ids = self.params.parties(); // Get parties from Parameters
        let threshold = self.params.threshold();
        let (vs, shares) = vss::create(&curve_params, threshold, ui.clone(), ids.as_vec(), &mut rng)
            .map_err(|e| self.wrap_keygen_error(e, vec![party_id.clone()]))?;
        data_guard.ks = ids.iter().map(|id| Some(id.key().clone())).collect(); // Store party keys (IDs)

        drop(ui); // Security: Clear secret ui

        // 3. Make commitment -> (C, D)
        // Flattening depends on the actual point type in Vs
        let vs_points_bytes: Vec<u8> = vs.iter().flat_map(|p| p.to_bytes()).collect(); // Placeholder to_bytes()
        let (cmt_c, cmt_d) = commitments::new_hash_commitment(&mut rng, &vs_points_bytes);

        // 4. Get PreParams (already in save_data)
        if data_guard.paillier_sk.is_none() || data_guard.paillier_pk.is_none() {
             return Err(self.wrap_keygen_error("Missing Paillier keys in save data".into(), vec![party_id.clone()]));
        }
        let paillier_sk = data_guard.paillier_sk.as_ref().unwrap();
        let paillier_pk = data_guard.paillier_pk.as_ref().unwrap();

        // Access N-tilde, h1, h2 etc. from temp_guard
        let n_tilde = temp_guard.n_tilde_i.as_ref().unwrap(); // Assuming pre-loaded
        let h1i = temp_guard.h1i.as_ref().unwrap();
        let h2i = temp_guard.h2i.as_ref().unwrap();
        let alpha = temp_guard.alpha.as_ref().unwrap();
        let beta = temp_guard.beta.as_ref().unwrap();
        let p_prime = temp_guard.p.as_ref().unwrap();
        let q_prime = temp_guard.q.as_ref().unwrap();

        // Generate DLN proofs
        let dln_proof_1 = dlnproof::new(h1i, h2i, alpha, p_prime, q_prime, n_tilde, &mut rng);
        let dln_proof_2 = dlnproof::new(h2i, h1i, beta, p_prime, q_prime, n_tilde, &mut rng);

        // Prepare SSID
        temp_guard.ssid_nonce = Some(BigInt::zero()); // Use nonce = 0 for now
        // SSID calculation requires access to sorted party IDs and curve params
        let ssid_participants: Vec<&BigInt> = self.params.parties().iter().map(|p| p.key()).collect();
        let ssid_prefix = "Ed25519"; // Simple prefix
        let ssid_input: Vec<&[u8]> = vec![ssid_prefix.as_bytes()]
            .into_iter()
            .chain(ssid_participants.iter().map(|k| k.to_bytes_be().1.as_slice()))
            .chain(std::iter::once(temp_guard.ssid_nonce.as_ref().unwrap().to_bytes_be().1.as_slice()))
            .collect();
        let ssid = hash_bytes(&ssid_input);
        temp_guard.ssid = Some(ssid);

        // Save data
        data_guard.share_id = Some(party_id.key().clone());
        // PaillierSK already in data_guard
        // PaillierPK already in data_guard
        temp_guard.vs = Some(vs); // Store VSS commitment points
        temp_guard.shares = Some(shares); // Store VSS shares
        temp_guard.de_commit_poly_g = Some(cmt_d); // Store decommitment

        // Broadcast Round 1 message
        let msg = messages::new_kg_round1_message(
            party_id,
            cmt_c,
            paillier_pk,
            n_tilde,
            h1i,
            h2i,
            &dln_proof_1,
            &dln_proof_2,
        )?;

        // Send the message
        self.out_channel.send(msg).map_err(|e| {
            self.wrap_keygen_error(Box::new(e), vec![]) // No specific culprits for send error
        })?;

        Ok(())
    }

    // Update is called by BaseParty when a message is stored.
    // It should check if the round can proceed.
    // The TssRound trait signature is &self, which is problematic for state changes.
    // Assuming BaseParty handles state or we use Mutex internally.
    fn update(&self) -> Result<(), TssError> {
        // This method in the base trait doesn't take a message.
        // Logic to check incoming messages and readiness to proceed
        // likely needs to happen elsewhere or the trait needs modification.
        // For now, this method might do nothing if BaseParty manages message checks.
        println!("Round 1 update called - checking if ready to proceed...");
        if self.can_proceed() {
             println!("Round 1 can proceed.");
             // BaseParty should call next_round? Or do we trigger proceed logic here?
             // Let's assume proceed logic happens when called externally after can_proceed is true.
        }
        Ok(())
    }

    // Check if we have received messages from all other parties
    fn can_proceed(&self) -> bool {
        let temp_guard = self.temp_data.lock().unwrap();
        temp_guard.round_1_messages.len() == self.params.party_count() - 1
    }

    // Parties we are waiting for messages from
    fn waiting_for(&self) -> Vec<PartyID> {
        let temp_guard = self.temp_data.lock().unwrap();
        self.params
            .parties()
            .iter()
            .filter(|p| *
                p != self.params.party_id()
                    && !temp_guard.round_1_messages.contains_key(p)
            )
            .cloned()
            .collect()
    }

    // Process received messages and transition to the next round.
    // BaseParty likely calls this when can_proceed() is true.
    // The trait signature is &self, making state transition difficult.
    // Assume this consumes self (or requires &mut self).
    fn next_round(&self) -> Box<dyn TssRound> {
        // TODO: Adapt this logic. This needs to consume self or take &mut self.
        // It should perform final round 1 logic (if any) and create Round 2.
        // Needs access to channels etc.
        println!("Transitioning from Round 1 to Round 2");

        // Placeholder: Create Round 2 - requires Round 2::new signature update
        // Round2::new(self.params.clone(), self.save_data.clone(), self.temp_data.clone(), self.out_channel.clone(), self.end_channel.clone())
        unimplemented!("next_round needs &mut self or consumes self, and Round2 integration")
    }

     // Wrap error using the KeygenRound helper
    fn wrap_error(&self, err: Box<dyn Error>, culprits: Vec<PartyID>) -> TssError {
        self.wrap_keygen_error(err, culprits)
    }
}
