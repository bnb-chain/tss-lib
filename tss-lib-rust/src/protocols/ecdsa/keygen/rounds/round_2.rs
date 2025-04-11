// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/ecdsa/keygen/round_2.go

use crate::{
    common::{task_name::TASK_NAME},
    crypto::{
        facproof,
        modproof,
    },
    protocols::ecdsa::keygen::{
        types::{LocalPartySaveData, LocalTempData},
        messages::{KGRound1Message, KGRound2Message1, KGRound2Message2},
        rounds::{Round3, dln_proof_verifier::{DlnProofVerifier, DlnProofVerifierContext}}, // Import for NextRound & Verifier
        verify_dln::verify_dln_proofs,
    },
    tss::{
        message::{TssMessage, ParsedMessage, MessageContent, MessageRoutingInfo, ParsedMessageImpl},
        round::{Round, RoundError, RoundErr, BaseRound},
        params::Parameters,
        party_id::PartyID,
    },
};

use std::{{
    sync::{Arc, Mutex, mpsc::Sender},
    collections::HashMap,
}};
use num_bigint_dig::{{BigInt, Sign}};
use num_traits::Zero;
use log::{info, debug, warn, error};
use anyhow::{Result, anyhow, Context};
use hex;

// Consistent with Go version
const PAILLIER_BITS_LEN: usize = 2048;

pub struct Round2 {
    base: BaseRound,
    params: Arc<Parameters>,
    save: Arc<Mutex<LocalPartySaveData>>,
    temp: Arc<Mutex<LocalTempData>>,
    out_ch: Sender<Box<dyn TssMessage + Send>>,
    end_ch: Sender<LocalPartySaveData>,
}

impl Round2 {
    pub fn new(
        params: Arc<Parameters>,
        save: Arc<Mutex<LocalPartySaveData>>,
        temp: Arc<Mutex<LocalTempData>>,
        out_ch: Sender<Box<dyn TssMessage + Send>>,
        end_ch: Sender<LocalPartySaveData>,
    ) -> Self {
        let base = BaseRound::new(2, params.party_count());
        Self {
            base,
            params,
            save,
            temp,
            out_ch,
            end_ch,
        }
    }
}

impl Round for Round2 {
    fn params(&self) -> &Parameters {
        &self.params
    }

    fn round_number(&self) -> i32 {
        self.base.round_number()
    }

    fn start(&self) -> Result<(), RoundError> {
        if self.base.started() {
            return Err(self.wrap_error(anyhow!("Round 2 already started"), vec![]));
        }
        self.base.set_started();
        self.base.reset_ok();

        let current_party_id = self.params.party_id();
        let i = current_party_id.index as usize;

         info!(target: "tss-lib", party_id = ?current_party_id, "Keygen Round 2 starting: Verifying DLN proofs, sending shares");

        // 6. Verify DLN proofs, store R1 message pieces, ensure uniqueness of h1j, h2j
         let temp_data_r1 = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;
         let round1_messages = temp_data_r1.message_store.kg_round1_messages.clone(); // Clone HashMap to avoid holding lock
         drop(temp_data_r1); // Release lock

         let mut h1h2_map = HashMap::with_capacity(self.params.party_count() * 2);
         let dln_contexts: Vec<DlnProofVerifierContext> = round1_messages.values().map(|parsed_msg_arc| {
            // Downcast and extract needed data
             let r1_msg: KGRound1Message = parsed_msg_arc
                .M::<KGRound1Message>()
                .map_err(|e| self.wrap_error(e, vec![parsed_msg_arc.from().clone()]))?;

             // Basic Validations (Paillier bit len, H1!=H2, Ntilde bit len)
             if r1_msg.paillier_pk.n.bits() != PAILLIER_BITS_LEN {
                 return Err(self.wrap_error(anyhow!("Paillier modulus has insufficient bits ({})", r1_msg.paillier_pk.n.bits()), vec![parsed_msg_arc.from().clone()]));
             }
             if r1_msg.h1 == r1_msg.h2 {
                 return Err(self.wrap_error(anyhow!("h1 and h2 are equal"), vec![parsed_msg_arc.from().clone()]));
             }
             if r1_msg.ntilde.bits() != PAILLIER_BITS_LEN {
                 return Err(self.wrap_error(anyhow!("Ntilde has insufficient bits ({})", r1_msg.ntilde.bits()), vec![parsed_msg_arc.from().clone()]));
             }

             // Uniqueness Check H1, H2
             let h1_hex = hex::encode(r1_msg.h1.to_bytes_be().1);
             let h2_hex = hex::encode(r1_msg.h2.to_bytes_be().1);
             if h1h2_map.contains_key(&h1_hex) || h1h2_map.contains_key(&h2_hex) {
                 return Err(self.wrap_error(anyhow!("h1 or h2 was already used by another party"), vec![parsed_msg_arc.from().clone()]));
             }
             h1h2_map.insert(h1_hex, ());
             h1h2_map.insert(h2_hex, ());

             Ok(DlnProofVerifierContext::new(r1_msg, parsed_msg_arc.from().clone()))
        }).collect::<Result<Vec<_>, RoundError>>()?;

         debug!(target: "tss-lib", party_id = ?current_party_id, concurrency = self.params.concurrency(), "Setting up DLN verification");
         let dln_results = verify_dln_proofs(&dln_contexts, self.params.concurrency())?;

         // Check results and collect culprits
         let mut culprits = Vec::new();
         for result in dln_results {
             if !result.proof1_valid || !result.proof2_valid {
                 error!(target: "tss-lib", party_id=?current_party_id, culprit=?result.culprit, proof1_ok=result.proof1_valid, proof2_ok=result.proof2_valid, "DLN proof failed");
                 culprits.push(result.culprit);
             }
         }
         if !culprits.is_empty() {
             return Err(self.wrap_error(anyhow!("DLN proof verification failed"), culprits));
         }
         info!(target: "tss-lib", party_id = ?current_party_id, "DLN proofs verified successfully");

         // Save data from R1 messages (PaillierPKs, NTildej, H1j, H2j, KGCs)
         {
             let mut save_data_lock = self.save.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock save data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             let mut temp_data_lock = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;

             for (party_idx, parsed_msg_arc) in &round1_messages {
                 let party_idx_usize = *party_idx as usize;
                 if party_idx_usize == i { continue; } // Skip self

                 // Safe to unwrap, already validated
                 let r1_msg = parsed_msg_arc.M::<KGRound1Message>().unwrap();

                 save_data_lock.paillier_pks[party_idx_usize] = Some(r1_msg.paillier_pk);
                 save_data_lock.ntilde_j[party_idx_usize] = Some(r1_msg.ntilde);
                 save_data_lock.h1j[party_idx_usize] = Some(r1_msg.h1);
                 save_data_lock.h2j[party_idx_usize] = Some(r1_msg.h2);
                 temp_data_lock.kgcs[party_idx_usize] = Some(r1_msg.commitment);
             }
         }

        // 5. P2P send VSS shares and Factorization proofs
         let (shares, own_sk_n, own_p, own_q, h1_vec, h2_vec, ntilde_vec) = {
             let temp_data_lock = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             let save_data_lock = self.save.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock save data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             (temp_data_lock.shares.clone().ok_or_else(|| self.wrap_error(anyhow!("Missing VSS shares"), vec![current_party_id.as_ref().clone()]))?,
              save_data_lock.paillier_sk.as_ref().map(|sk| sk.n().clone()).ok_or_else(|| self.wrap_error(anyhow!("Missing Paillier SK"), vec![current_party_id.as_ref().clone()]))?,
              save_data_lock.local_pre_params.p.clone(),
              save_data_lock.local_pre_params.q.clone(),
              save_data_lock.h1j.iter().map(|opt| opt.clone().unwrap()).collect::<Vec<_>>(), // Unwraps are safe due to previous checks/saves
              save_data_lock.h2j.iter().map(|opt| opt.clone().unwrap()).collect::<Vec<_>>(),
              save_data_lock.ntilde_j.iter().map(|opt| opt.clone().unwrap()).collect::<Vec<_>>(),
             )
         };

         let context_i = self.get_context_bytes(i as i32)?; // Context bytes including self index

         let all_parties = self.params.parties().party_ids();
         for (j, party_j) in all_parties.iter().enumerate() {
            let ntilde_j = &ntilde_vec[j];
            let h1_j = &h1_vec[j];
            let h2_j = &h2_vec[j];

             let fac_proof = if self.params.no_proof_fac() {
                 debug!(target: "tss-lib", party_id = ?current_party_id, to_party_idx=j, "Skipping FacProof generation");
                 facproof::ProofFac::empty_proof() // Assuming an empty proof method
             } else {
                 debug!(target: "tss-lib", party_id = ?current_party_id, to_party_idx=j, "Generating FacProof...");
                 facproof::ProofFac::new(
                     &context_i,
                     &self.params.ec().order(), // Curve order q
                     &own_sk_n,                 // N_i (Paillier N)
                     ntilde_j,                 // N^_j (Receiver's Ntilde)
                     h1_j,                      // s_j (Receiver's H1)
                     h2_j,                      // t_j (Receiver's H2)
                     &own_p,                    // p_i (Our Paillier factor)
                     &own_q,                    // q_i (Our Paillier factor)
                     &mut thread_rng(),         // Use proper RNG
                 )?
             };

             let r2msg1 = KGRound2Message1::new(
                 party_j.as_ref().clone(), // Destination
                 shares.get_share(j).clone(), // share_ij
                 fac_proof,
             );

             let routing = MessageRoutingInfo {
                 from: current_party_id.as_ref().clone(),
                 to: Some(vec![party_j.as_ref().clone()]), // P2P
                 is_broadcast: false,
                 is_to_old_committee: false,
                 is_to_old_and_new_committees: false,
             };
             let tss_msg = ParsedMessageImpl::from_content(routing, &r2msg1)?;

             // Store own message for R3, send to others
             if j == i {
                 let mut temp_data_lock = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;
                 temp_data_lock.message_store.kg_round2_message1s.insert(i as i32, Arc::new(tss_msg));
             } else {
                 debug!(target: "tss-lib", party_id = ?current_party_id, to_party_idx=j, "Sending share and FacProof");
                 self.out_ch.send(Box::new(tss_msg))
                     .map_err(|e| self.wrap_error(anyhow!("Failed to send Round2 Message1: {}", e), vec![]))?;
             }
         }

        // 7. BROADCAST de-commitments D_i and ModProof
         let (decommitment_di, paillier_sk_n, paillier_sk_p, paillier_sk_q) = {
             let mut temp_data_lock = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             let save_data_lock = self.save.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock save data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             (temp_data_lock.decommit_poly_g.take().ok_or_else(|| self.wrap_error(anyhow!("Missing VSS decommitment"), vec![current_party_id.as_ref().clone()]))?,
              save_data_lock.paillier_sk.as_ref().map(|sk| sk.n().clone()).ok_or_else(|| self.wrap_error(anyhow!("Missing Paillier SK"), vec![current_party_id.as_ref().clone()]))?,
              save_data_lock.local_pre_params.p.clone(),
              save_data_lock.local_pre_params.q.clone(),
             )
         };

         let mod_proof = if self.params.no_proof_mod() {
             debug!(target: "tss-lib", party_id = ?current_party_id, "Skipping ModProof generation");
             modproof::ProofMod::empty_proof() // Assuming an empty proof method
         } else {
             debug!(target: "tss-lib", party_id = ?current_party_id, "Generating ModProof...");
             modproof::ProofMod::new(
                 &context_i,
                 &paillier_sk_n, // N_i
                 &paillier_sk_p, // p_i
                 &paillier_sk_q, // q_i
                 &mut thread_rng(), // Use proper RNG
             )?
         };

         let r2msg2 = KGRound2Message2::new(decommitment_di, mod_proof);
         let routing = MessageRoutingInfo {
             from: current_party_id.as_ref().clone(),
             to: None, // Broadcast
             is_broadcast: true,
             is_to_old_committee: false,
             is_to_old_and_new_committees: false,
         };
         let tss_msg = ParsedMessageImpl::from_content(routing, &r2msg2)?;

         // Store own message
         {
             let mut temp_data_lock = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             temp_data_lock.message_store.kg_round2_message2s.insert(i as i32, Arc::new(tss_msg.clone()));
         }

         // Send broadcast message
         debug!(target: "tss-lib", party_id = ?current_party_id, "Broadcasting decommitment and ModProof");
         self.out_ch.send(Box::new(tss_msg))
             .map_err(|e| self.wrap_error(anyhow!("Failed to send Round2 Message2: {}", e), vec![]))?;

        info!(target: "tss-lib", party_id = ?current_party_id, "Keygen Round 2 finished successfully");
        Ok(())
    }

    fn can_accept(&self, msg: &dyn ParsedMessage) -> bool {
        let from = msg.from();
        // Ensure message is from a valid party index
        if from.index < 0 || from.index as usize >= self.params.party_count() {
            warn!(target:"tss-lib", party_id=?self.params.party_id(), from_party=?from, "Message from invalid party index ignored");
            return false;
        }
        match msg.type_url().as_str() {
            KGRound2Message1::TYPE_URL => !msg.is_broadcast(), // P2P
            KGRound2Message2::TYPE_URL => msg.is_broadcast(),  // Broadcast
            _ => false,
        }
    }

    fn update(&self) -> Result<bool, RoundError> {
        let mut all_ok = true;
        let required_parties = self.params.party_count();

        let temp_data = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![]))?;

        for j in 0..required_parties {
            if self.base.is_ok(j) { continue; }
            // Check if both Message1 and Message2 are received from party j
            if temp_data.message_store.kg_round2_message1s.contains_key(&(j as i32)) &&
               temp_data.message_store.kg_round2_message2s.contains_key(&(j as i32))
            {
                self.base.set_ok(j);
            } else {
                all_ok = false;
            }
        }
         debug!(target: "tss-lib", party_id = ?self.params.party_id(), ok_parties = ?self.base.get_ok_vec(), "Round 2 update check");
        Ok(all_ok)
    }

    fn next_round(&self) -> Option<Arc<dyn Round>> {
        self.base.set_started_unwrapped();
         Some(Arc::new(Round3::new(
            self.params.clone(),
            self.save.clone(),
            self.temp.clone(),
            self.out_ch.clone(),
            self.end_ch.clone(),
        )))
    }

    fn waiting_for(&self) -> Vec<PartyID> {
        let party_ids = self.params.parties().party_ids();
        self.base.waiting_for(party_ids)
    }

}

// Helper to get context bytes (SSID || index)
impl Round2 {
    fn get_context_bytes(&self, index: i32) -> Result<Vec<u8>, RoundError> {
         let temp_data = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![]))?;
         let ssid = temp_data.ssid.as_ref().ok_or_else(|| self.wrap_error(anyhow!("Missing SSID"), vec![]))?;
         let mut context_bytes = ssid.clone();
         context_bytes.extend_from_slice(&index.to_be_bytes());
         Ok(context_bytes)
    }
} 