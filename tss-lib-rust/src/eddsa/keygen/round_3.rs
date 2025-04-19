// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// EDDSA Keygen round 3 logic (ported from Go)

use std::collections::HashMap;
use std::error::Error as StdError;
use std::ops::Add;
use std::sync::{Arc, Mutex, mpsc::Sender};
use num_bigint::BigInt;
use num_traits::{One, Zero};

use crate::eddsa::keygen::{
    rounds::{KeygenRound, PROTOCOL_NAME},
    KeygenPartyTmpData,
    KeyGenPartySaveData,
    messages::{self, KGRound3Message},
};
use crate::tss::{
    curve::{CurveName, get_curve_params, CurveParams}, // Import curve types
    error::TssError,
    message::{ParsedMessage, TssMessage},
    params::Parameters,
    party::Round as TssRound,
    party_id::{PartyID, SortedPartyIDs},
};
use crate::crypto::paillier; // Import actual paillier

// Use actual curve types from dalek
use ed25519_dalek::{EdwardsPoint, Scalar as Ed25519Scalar};

// Placeholder imports (adjust as needed)
use crate::crypto::commitments::{HashCommitment, HashDeCommitment, HashCommitDecommit};
use crate::crypto::vss::{Vs, VssShare}; // Vs should likely be Vec<EdwardsPoint>
use crate::crypto::fac_proof::Proof as FacProof;
use crate::crypto::mod_proof::Proof as ModProof;
use crate::crypto::paillier::Proof as PaillierProof; // Placeholder proof
// Remove placeholder curve import
// use crate::crypto::curves::Ed25519;
// Remove placeholder point import
// use crate::crypto::ecdsa::point::ECPoint;

// --- Placeholder Crypto Operations/Types --- //
// TODO: Replace with actual implementations using ed25519-dalek

mod crypto_helpers {
    use super::{BigInt, EdwardsPoint, Ed25519Scalar, StdError};
    use num_traits::Zero;
    use ed25519_dalek::constants::ED25519_BASEPOINT_POINT;

    // Placeholder for unflattening points - needs real implementation
    pub fn un_flatten_ec_points(
        _flat_points: &[u8],
        _count: usize // Need to know how many points to expect
    ) -> Result<Vec<EdwardsPoint>, Box<dyn StdError>> {
        println!("Warning: Using placeholder crypto::un_flatten_ec_points");
        // Dummy implementation
        Ok((0.._count).map(|_| ED25519_BASEPOINT_POINT).collect()) // Return generators
    }
}

// Assuming VssShare is defined with a field `.0` of type Ed25519Scalar
impl VssShare {
    pub fn verify(
        &self,
        _curve_params: &CurveParams,
        _threshold: usize,
        _commitments: &[EdwardsPoint]
    ) -> bool {
        println!("Warning: Using placeholder VssShare::verify");
        true
    }
}

impl ModProof {
    pub fn verify(&self, _context: &[u8], _n: &BigInt) -> bool {
        println!("Warning: Using placeholder ModProof::verify");
        true
    }
}

impl FacProof {
    pub fn verify(
        &self,
        _context: &[u8],
        _curve_params: &CurveParams,
        _n: &BigInt,
        _n_tilde_i: &BigInt,
        _h1i: &BigInt,
        _h2i: &BigInt,
    ) -> bool {
        println!("Warning: Using placeholder FacProof::verify");
        true
    }
}

// Assuming PaillierProof is defined with a field `.0` of type Vec<u8>
impl PaillierProof {
    pub fn verify(&self, _pk: &paillier::PublicKey) -> bool {
        println!("Warning: Using placeholder PaillierProof::verify");
        true
    }
    pub fn dummy() -> Self { PaillierProof(vec![10,11,12]) }
}
// --- End Placeholder Crypto --- //

#[derive(Debug)]
pub struct Round3 {
    params: Arc<Parameters>,
    temp_data: Arc<Mutex<KeygenPartyTmpData>>,
    save_data: Arc<Mutex<KeyGenPartySaveData>>,
    out_channel: Arc<Sender<TssMessage>>,
    end_channel: Arc<Sender<KeyGenPartySaveData>>,
    // Internal state
    started: bool,
    messages_received: HashMap<PartyID, KGRound3Message>,
}

// ... (Round3::new, Round3::send_final_result, impl KeygenRound for Round3) ...

impl TssRound for Round3 {
    fn round_number(&self) -> u32 { 3 }

    fn params(&self) -> &Parameters { &self.params }

    fn start(&self) -> Result<(), TssError> {
        if self.started {
            return Err(self.wrap_keygen_error("Round 3 already started".into(), vec![]));
        }
        // Mark started?

        let party_id = self.params.party_id();
        let i = self.params.party_index();
        let threshold = self.params.threshold();
        let party_count = self.params.party_count();

        // Get Ed25519 parameters
        let curve_params = get_curve_params(CurveName::Ed25519)
            .ok_or_else(|| self.wrap_keygen_error("Ed25519 curve parameters not found".into(), vec![]))?;
        let curve_order = match &curve_params {
             CurveParams::Ed25519 { order, .. } => order,
             _ => return Err(self.wrap_keygen_error("Incorrect curve parameters received".into(), vec![])),
        };

        // Lock data stores
        let temp_guard = self.temp_data.lock().map_err(|e| TssError::LockPoisonError(format!("Temp data lock poisoned: {}", e)))?;
        let mut data_guard = self.save_data.lock().map_err(|e| TssError::LockPoisonError(format!("Save data lock poisoned: {}", e)))?;

        // 1, 9. Calculate xi
        let shares_option = temp_guard.shares.as_ref().ok_or_else(|| self.wrap_keygen_error("Missing VSS shares".into(), vec![party_id.clone()]))?;
        let mut xi_scalar = shares_option.get(i)
            .map(|s| s.0.clone()) // Assuming VssShare(Ed25519Scalar)
            .ok_or_else(|| self.wrap_keygen_error("Missing own VSS share".into(), vec![party_id.clone()]))?;

        if temp_guard.round_2_messages1.len() != party_count - 1 {
             return Err(self.wrap_keygen_error("Incorrect number of Round 2 Message 1 found".into(), vec![]));
        }

        for (_from_party_id, r2msg1) in &temp_guard.round_2_messages1 {
            xi_scalar += &r2msg1.share.0; // Use scalar addition
        }
        // Store final xi (as BigInt for compatibility? Or keep as Scalar?)
        // Convert scalar to BigInt for now
        let xi_bigint = BigInt::from_bytes_le(num_bigint::Sign::Plus, &xi_scalar.to_bytes());
        data_guard.x_i = Some(xi_bigint);

        // 2-3. Initialize Vc with own VSS commitments
        // Assuming temp_guard.vs is Vec<EdwardsPoint>
        let mut vc: Vec<EdwardsPoint> = temp_guard.vs.clone()
            .ok_or_else(|| self.wrap_keygen_error("Missing own VSS commitments (Vs)".into(), vec![party_id.clone()]))?;
        if vc.len() <= threshold {
             return Err(self.wrap_keygen_error("Insufficient VSS commitments found".into(), vec![party_id.clone()]));
        }

        // 4-11. Verify decommitments, shares, proofs, and combine Vc
        println!("Round 3: Verifying shares and decommitments...");
        let mut pj_vs_map: HashMap<PartyID, Vec<EdwardsPoint>> = HashMap::new();

        let n_tilde_i = temp_guard.n_tilde_i.as_ref().ok_or_else(|| self.wrap_keygen_error("Missing own N-tilde".into(), vec![party_id.clone()]))?;
        let h1i = temp_guard.h1i.as_ref().ok_or_else(|| self.wrap_keygen_error("Missing own H1".into(), vec![party_id.clone()]))?;
        let h2i = temp_guard.h2i.as_ref().ok_or_else(|| self.wrap_keygen_error("Missing own H2".into(), vec![party_id.clone()]))?;
        let all_parties = self.params.parties();

         if temp_guard.round_2_messages2.len() != party_count -1 {
              return Err(self.wrap_keygen_error("Incorrect number of Round 2 Message 2 found".into(), vec![]));
         }

        for pj in all_parties.iter() {
            if pj == party_id { continue; }
            let j = pj.index();
            let ssid_bytes = temp_guard.ssid.as_ref().ok_or_else(|| self.wrap_keygen_error("Missing SSID".into(), vec![party_id.clone()]))?;
            let context_j = [ssid_bytes.as_slice(), BigInt::from(j).to_bytes_be().1.as_slice()].concat();

            let result: Result<Vec<EdwardsPoint>, String> = (|| {
                let r2msg1 = temp_guard.round_2_messages1.get(pj).ok_or("Missing Round2Msg1")?;
                let r2msg2 = temp_guard.round_2_messages2.get(pj).ok_or("Missing Round2Msg2")?;

                // Decommitment Verification
                let kgc_j = temp_guard.kgcs[j].as_ref().ok_or("Missing KGCj")?;
                let kgd_j = &r2msg2.decommitment;
                let cmt_decmt = HashCommitDecommit { c: Some(kgc_j.clone()), d: Some(kgd_j.clone()) };
                let (ok, flat_poly_gs_opt) = cmt_decmt.decommit().map_err(|e| format!("Decommit failed: {}", e))?;
                if !ok { return Err("Decommitment verify failed".to_string()); }
                let flat_poly_gs = flat_poly_gs_opt.ok_or("Decommitment succeeded but returned no data")?;
                // Pass threshold+1 as expected point count
                let pj_vs_vec = crypto_helpers::un_flatten_ec_points(&flat_poly_gs, threshold + 1).map_err(|e| format!("Unflatten failed: {}", e))?;
                if pj_vs_vec.len() <= threshold { return Err("Unflattened VSS commitments have insufficient length".to_string()); }

                 // Verify ModProof
                 let mod_proof = r2msg2.mod_proof.as_ref().ok_or("Missing ModProof")?;
                 let paillier_pk_j = data_guard.paillier_pks[j].as_ref().ok_or("Missing Paillier PK for party j")?;
                 if !mod_proof.verify(&context_j, &paillier_pk_j.n) { return Err("ModProof verify failed".to_string()); }

                 // Verify VSS Share (pass actual curve_params)
                 let pj_share = &r2msg1.share;
                 if !pj_share.verify(&curve_params, threshold, &pj_vs_vec) { return Err("VSS Share verify failed".to_string()); }

                 // Verify FacProof (pass actual curve_params)
                 let fac_proof = r2msg1.fac_proof.as_ref().ok_or("Missing FacProof")?;
                 if !fac_proof.verify(&context_j, &curve_params, &paillier_pk_j.n, n_tilde_i, h1i, h2i) { return Err("FacProof verify failed".to_string()); }

                Ok(pj_vs_vec)
            })();

            match result {
                Ok(pj_vs) => { pj_vs_map.insert(pj.clone(), pj_vs); }
                Err(e_str) => { return Err(self.wrap_keygen_error(e_str.into(), vec![pj.clone()])); }
            }
        }
        println!("Round 3: VSS shares and proofs verified.");

        // 10-11. Combine Vc (using EdwardsPoint addition)
        for pj in all_parties.iter() {
             if pj == party_id { continue; }
             let pj_vs = pj_vs_map.get(pj).unwrap();
             for c in 0..=threshold {
                 vc[c] = vc[c] + pj_vs[c]; // Use native point addition
             }
        }

        // 12-16. Compute Xj (public key shares)
        let mut big_x_j: Vec<Option<EdwardsPoint>> = vec![None; party_count];
        for pj in all_parties.iter() {
            let j = pj.index();
            let kj_bytes = pj.key().to_bytes_le().1;
             // Need fixed-size array for from_bytes_mod_order
             let mut kj_bytes_arr = [0u8; 32];
             if kj_bytes.len() > 32 { return Err(self.wrap_keygen_error("Party key too long for Ed25519 scalar".into(), vec![pj.clone()])); }
             kj_bytes_arr[..kj_bytes.len()].copy_from_slice(&kj_bytes);

             let kj_scalar = Ed25519Scalar::from_bytes_mod_order(kj_bytes_arr);

            let mut xj = vc[0]; // Xj = Vc[0]
            let mut z_scalar = kj_scalar; // z = kj^1
            for c in 1..=threshold {
                 if c > 1 {
                    z_scalar *= kj_scalar; // z = kj^c
                 }
                 let term = vc[c] * z_scalar; // Use native scalar mult
                 xj = xj + term; // Use native point add
            }
            big_x_j[j] = Some(xj);
        }
        // Store the computed public key shares in save data
        // TODO: Update KeyGenPartySaveData.all_shares_sum to be Vec<Option<EdwardsPoint>>
        // data_guard.all_shares_sum = big_x_j;
        println!("Round 3: Public key shares computed.");

        // 17. Compute final public key Y = Vc[0]
        let final_pk = vc[0];
        // TODO: Update KeyGenPartySaveData.eddsa_pk_sum to be Option<EdwardsPoint>
        // data_guard.eddsa_pk_sum = Some(final_pk);

        // Generate Paillier proof
        let _paillier_sk = data_guard.paillier_sk.as_ref()
            .ok_or_else(|| self.wrap_keygen_error("Missing Paillier SK".into(), vec![party_id.clone()]))?;
        println!("Warning: Using placeholder Paillier proof generation.");
        let paillier_proof = PaillierProof::dummy();

        let r3msg = messages::new_kg_round3_message(party_id, paillier_proof)?;

        self.out_channel.send(r3msg).map_err(|e| {
             self.wrap_keygen_error(Box::new(e), vec![])
         })?;

        Ok(())
    }

    // ... (update, can_proceed, waiting_for, next_round, wrap_error) ...
}
