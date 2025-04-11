// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/ecdsa/keygen/round_3.go

use crate::{
    common::task_name::TASK_NAME,
    crypto::{
        commitments::hash::HashCommitment,
        ecpoint::ECPoint,
        facproof,
        modproof,
        vss,
    },
    protocols::ecdsa::keygen::{
        types::{LocalPartySaveData, LocalTempData},
        messages::{KGRound2Message1, KGRound2Message2, KGRound3Message},
        rounds::{Round4, verify_vss::{VssVerifyContext, verify_vss_share_and_proofs}}, // Import for NextRound & VSS Verify
    },
    tss::{
        message::{TssMessage, ParsedMessage, MessageContent, MessageRoutingInfo, ParsedMessageImpl},
        round::{Round, RoundError, RoundErr, BaseRound},
        params::Parameters,
        party_id::PartyID,
        curve::Curve,
    },
};

use std::{{
    sync::{Arc, Mutex, mpsc::Sender},
}};
use num_bigint_dig::{{BigInt, Sign}};
use num_traits::Zero;
use log::{info, debug, warn, error};
use anyhow::{Result, anyhow, Context};
use std::collections::HashMap;

pub struct Round3 {
    base: BaseRound,
    params: Arc<Parameters>,
    save: Arc<Mutex<LocalPartySaveData>>,
    temp: Arc<Mutex<LocalTempData>>,
    out_ch: Sender<Box<dyn TssMessage + Send>>,
    end_ch: Sender<LocalPartySaveData>,
}

impl Round3 {
    pub fn new(
        params: Arc<Parameters>,
        save: Arc<Mutex<LocalPartySaveData>>,
        temp: Arc<Mutex<LocalTempData>>,
        out_ch: Sender<Box<dyn TssMessage + Send>>,
        end_ch: Sender<LocalPartySaveData>,
    ) -> Self {
        let base = BaseRound::new(3, params.party_count());
        Self {
            base,
            params,
            save,
            temp,
            out_ch,
            end_ch,
        }
    }

    /// Helper to get context bytes (SSID || index)
    fn get_context_bytes(&self, index: i32) -> Result<Vec<u8>, RoundError> {
         let temp_data = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![]))?;
         let ssid = temp_data.ssid.as_ref().ok_or_else(|| self.wrap_error(anyhow!("Missing SSID"), vec![]))?;
         let mut context_bytes = ssid.clone();
         context_bytes.extend_from_slice(&index.to_be_bytes());
         Ok(context_bytes)
    }
}

impl Round for Round3 {
    fn params(&self) -> &Parameters {
        &self.params
    }

    fn round_number(&self) -> i32 {
        self.base.round_number()
    }

    fn start(&self) -> Result<(), RoundError> {
        if self.base.started() {
            return Err(self.wrap_error(anyhow!("Round 3 already started"), vec![]));
        }
        self.base.set_started();
        self.base.reset_ok();

        let current_party_id = self.params.party_id();
        let i_usize = current_party_id.index as usize;

         info!(target: "tss-lib", party_id = ?current_party_id, "Keygen Round 3 starting: Verifying VSS shares and proofs");

        // 1, 9. Calculate private key share x_i
        let xi = {
            let temp_data_lock = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;
            let own_share = temp_data_lock.shares.as_ref()
                .ok_or_else(|| self.wrap_error(anyhow!("Missing own VSS shares"), vec![current_party_id.as_ref().clone()]))?
                .get_share(i_usize);

             let mut xi_acc = own_share.clone();
            let ec_order = self.params.ec().order();

             for (j, p2p_msg_arc) in &temp_data_lock.message_store.kg_round2_message1s {
                let j_usize = *j as usize;
                if j_usize == i_usize { continue; }

                 // Should be safe to unwrap as R2 ensures all messages are received
                 let r2msg1 = p2p_msg_arc.M::<KGRound2Message1>()
                    .map_err(|e| self.wrap_error(e, vec![p2p_msg_arc.from().clone()]))?;

                 xi_acc = (&xi_acc + &r2msg1.share).mod_floor(&ec_order); // xi = sum(share_ji) mod q
            }
            xi_acc
        };

        {
             let mut save_data_lock = self.save.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock save data: {}", e), vec![current_party_id.as_ref().clone()]))?;
            save_data_lock.xi = Some(xi); // Save calculated private key share
        }

        // 2-3. Vc = Sum(V_cj) mod N
         let mut combined_vss_commitments: Vec<ECPoint<Curve>> = Vec::new(); // Initialize with identity or handle first element specially
         let mut vss_contexts: Vec<VssVerifyContext> = Vec::with_capacity(self.params.party_count());

         // Prepare verification contexts and combine Vc commitments
         {
             let temp_data_lock = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             let save_data_lock = self.save.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock save data: {}", e), vec![current_party_id.as_ref().clone()]))?;

             for j in 0..self.params.party_count() {
                 let party_j = &self.params.parties().party_ids()[j];
                 let context_j = self.get_context_bytes(j as i32)?; // Context bytes for party j

                 // Get messages and data for party j
                 let r2msg1_arc = temp_data_lock.message_store.kg_round2_message1s.get(&(j as i32))
                     .ok_or_else(|| self.wrap_error(anyhow!("Missing Round2 Message1 for party {}", j), vec![party_j.as_ref().clone()]))?;
                 let r2msg2_arc = temp_data_lock.message_store.kg_round2_message2s.get(&(j as i32))
                     .ok_or_else(|| self.wrap_error(anyhow!("Missing Round2 Message2 for party {}", j), vec![party_j.as_ref().clone()]))?;

                 // Downcast to concrete types (should be safe after R2 update)
                 let r2msg1 = r2msg1_arc.M::<KGRound2Message1>().unwrap();
                 let r2msg2 = r2msg2_arc.M::<KGRound2Message2>().unwrap();

                 let vss_commitment_c_j = temp_data_lock.kgcs[j].as_ref()
                      .ok_or_else(|| self.wrap_error(anyhow!("Missing commitment C_{}", j), vec![party_j.as_ref().clone()]))?;
                 let vss_decommitment_d_j = r2msg2.decommitment.clone();
                 let received_vss_share_ij = vss::Share {
                     threshold: self.params.threshold(),
                     id: current_party_id.key.clone(), // Our ID
                     share: r2msg1.share.clone(),
                 };
                 let paillier_pk_j = save_data_lock.paillier_pks[j].as_ref()
                     .ok_or_else(|| self.wrap_error(anyhow!("Missing Paillier PK for party {}", j), vec![party_j.as_ref().clone()]))?;
                 let n_tilde_j = save_data_lock.ntilde_j[j].as_ref()
                      .ok_or_else(|| self.wrap_error(anyhow!("Missing Ntilde for party {}", j), vec![party_j.as_ref().clone()]))?;
                 let h1_j = save_data_lock.h1j[j].as_ref()
                      .ok_or_else(|| self.wrap_error(anyhow!("Missing H1 for party {}", j), vec![party_j.as_ref().clone()]))?;
                 let h2_j = save_data_lock.h2j[j].as_ref()
                      .ok_or_else(|| self.wrap_error(anyhow!("Missing H2 for party {}", j), vec![party_j.as_ref().clone()]))?;

                 // Decommit VSS commitment C_j to get V_cj = [g^a_c0, ..., g^a_ct]
                 let hash_commit_decommit = HashCommitment::new(vss_commitment_c_j.clone(), vss_decommitment_d_j.clone());
                 let vss_points_j = hash_commit_decommit.decommit()
                     .map_err(|e| self.wrap_error(e, vec![party_j.as_ref().clone()]))?;

                 // Combine V_cj points
                  if combined_vss_commitments.is_empty() {
                      combined_vss_commitments = vss_points_j;
                  } else {
                      if combined_vss_commitments.len() != vss_points_j.len() {
                          return Err(self.wrap_error(anyhow!("VSS commitment length mismatch from party {}", j), vec![party_j.as_ref().clone()]));
                      }
                      for c in 0..combined_vss_commitments.len() {
                          combined_vss_commitments[c] = combined_vss_commitments[c].add(&vss_points_j[c])?;
                      }
                  }

                 // Prepare context for concurrent verification
                 vss_contexts.push(VssVerifyContext {
                     party_index: j,
                     commitment_c_j: vss_commitment_c_j.clone(),
                     decommitment_d_j: vss_decommitment_d_j.clone(),
                     mod_proof: r2msg2.mod_proof.clone(),
                     fac_proof: r2msg1.fac_proof.clone(),
                     received_vss_share_ij,
                     paillier_pk_j: paillier_pk_j.clone(),
                     n_tilde_j: n_tilde_j.clone(),
                     h1_j: h1_j.clone(),
                     h2_j: h2_j.clone(),
                     context_j,
                     no_proof_mod: self.params.no_proof_mod(),
                     no_proof_fac: self.params.no_proof_fac(),
                 });
             }
         }

        // 4-11. Verify VSS shares, ModProof, FacProof concurrently
         debug!(target: "tss-lib", party_id = ?current_party_id, concurrency = self.params.concurrency(), "Verifying VSS shares and proofs...");
        let verification_results = verify_vss_share_and_proofs(
            vss_contexts,
            self.params.ec(),
            self.params.threshold(),
            current_party_id.as_ref().clone(),
            self.params.concurrency(),
        )?;

         // Check verification results
         let mut culprits = Vec::new();
         for result in verification_results {
             if !result.is_valid() {
                  error!(target: "tss-lib", party_id=?current_party_id, failed_party_idx=result.party_index, error=?result.error_reason, "VSS/Proof verification failed");
                 culprits.push(self.params.parties().party_ids()[result.party_index].as_ref().clone());
             }
         }
         if !culprits.is_empty() {
             return Err(self.wrap_error(anyhow!("VSS share or proof verification failed"), culprits));
         }
         info!(target: "tss-lib", party_id = ?current_party_id, "VSS shares and proofs verified successfully");

        // 12-16. Calculate X_j = g^x_j for each Pj
         let big_x_j = {
             let curve = self.params.ec();
             let order = curve.order();
             let mut xs: Vec<Option<ECPoint<Curve>>> = vec![None; self.params.party_count()];

             for j in 0..self.params.party_count() {
                 let party_j = &self.params.parties().party_ids()[j];
                 let party_j_key = &party_j.key;
                 let mut x_j = combined_vss_commitments[0].clone(); // X_j = V_0j * Product(V_cj ^ (k_j^c)) for c=1..t
                 let mut k_pow_c = BigInt::one();

                 for c in 1..=self.params.threshold() {
                     k_pow_c = (&k_pow_c * party_j_key).mod_floor(&order);
                     let v_cj = &combined_vss_commitments[c];
                     let v_cj_pow_k = v_cj.scalar_mul(&k_pow_c);
                     x_j = x_j.add(&v_cj_pow_k)?; // Add points
                 }
                 xs[j] = Some(x_j);
             }
             xs
         };

        // 17. Compute and SAVE the ECDSA public key y = V_0 = g^x
         let pk_point = combined_vss_commitments[0].clone(); // y = V_0
         info!(target: "tss-lib", party_id = ?current_party_id, ecdsa_pk = ?pk_point, "ECDSA Public Key Computed");

         // PRINT private share (optional, for debug/verification)
          let xi_saved = self.save.lock().unwrap().xi.clone().unwrap();
          debug!(target: "tss-lib", party_id = ?current_party_id, private_share_xi = ?xi_saved, "Private key share computed");

         // Save final state
         {
             let mut save_data_lock = self.save.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock save data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             save_data_lock.big_xj = big_x_j; // Save Xj for all j
             save_data_lock.ecdsa_pub = Some(pk_point); // Save final public key
         }

        // BROADCAST Paillier Proof
         let (paillier_sk, ecdsa_pub_key) = {
             let save_data_lock = self.save.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock save data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             (save_data_lock.paillier_sk.clone().ok_or_else(|| self.wrap_error(anyhow!("Missing Paillier SK"), vec![current_party_id.as_ref().clone()]))?,
              save_data_lock.ecdsa_pub.clone().ok_or_else(|| self.wrap_error(anyhow!("Missing ECDSA PubKey"), vec![current_party_id.as_ref().clone()]))?)
         };

         let paillier_proof = paillier_sk.prove(&current_party_id.key, &ecdsa_pub_key)
             .map_err(|e| self.wrap_error(e, vec![current_party_id.as_ref().clone()]))?;

         let r3msg = KGRound3Message::new(paillier_proof);
         let routing = MessageRoutingInfo {
             from: current_party_id.as_ref().clone(),
             to: None, // Broadcast
             is_broadcast: true,
             is_to_old_committee: false,
             is_to_old_and_new_committees: false,
         };
         let tss_msg = ParsedMessageImpl::from_content(routing, &r3msg)?;

         // Store own message
         {
             let mut temp_data_lock = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             temp_data_lock.message_store.kg_round3_messages.insert(i_usize as i32, Arc::new(tss_msg.clone()));
         }

         // Send broadcast message
         debug!(target: "tss-lib", party_id = ?current_party_id, "Broadcasting Paillier proof");
         self.out_ch.send(Box::new(tss_msg))
             .map_err(|e| self.wrap_error(anyhow!("Failed to send Round3 message: {}", e), vec![]))?;

        info!(target: "tss-lib", party_id = ?current_party_id, "Keygen Round 3 finished successfully");
        Ok(())
    }

    fn can_accept(&self, msg: &dyn ParsedMessage) -> bool {
        msg.is_broadcast() && msg.type_url() == KGRound3Message::TYPE_URL
    }

    fn update(&self) -> Result<bool, RoundError> {
        let mut all_ok = true;
        let required_count = self.params().party_count();

        let temp_data = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![]))?;

        for j in 0..required_count {
            if self.base.is_ok(j) { continue; }
            if temp_data.message_store.kg_round3_messages.contains_key(&(j as i32)) {
                self.base.set_ok(j);
            } else {
                all_ok = false;
            }
        }
         debug!(target: "tss-lib", party_id = ?self.params.party_id(), ok_parties = ?self.base.get_ok_vec(), "Round 3 update check");
        Ok(all_ok)
    }

    fn next_round(&self) -> Option<Arc<dyn Round>> {
        self.base.set_started_unwrapped();
         Some(Arc::new(Round4::new(
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