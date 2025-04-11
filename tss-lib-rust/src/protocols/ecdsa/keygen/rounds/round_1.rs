// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/ecdsa/keygen/round_1.go

use crate::{
    common::{
        safe_prime::SafePrimeGenerator,
        random::get_random_positive_int,
        task_name::TASK_NAME,
    },
    crypto::{
        commitments::hash::HashCommitment,
        dlnproof,
        vss,
    },
    protocols::ecdsa::keygen::{
        types::{LocalPartySaveData, LocalTempData, LocalPreParams},
        messages::{KGRound1Message},
        rounds::Round2, // Import for NextRound
    },
    tss::{
        message::{TssMessage, ParsedMessage, MessageContent, MessageRoutingInfo},
        round::{Round, RoundError, RoundErr, BaseRound},
        params::Parameters,
        party_id::PartyID,
    },
};

use std::{{
    sync::{Arc, Mutex, mpsc::Sender},
}};
use num_bigint_dig::{{BigInt, Sign}};
use num_traits::Zero;
use log::{info, debug};
use anyhow::{Result, anyhow, Context};
use rand::thread_rng;

pub struct Round1 {
    base: BaseRound,
    params: Arc<Parameters>,
    save: Arc<Mutex<LocalPartySaveData>>,
    temp: Arc<Mutex<LocalTempData>>,
    out_ch: Sender<Box<dyn TssMessage + Send>>,
    end_ch: Sender<LocalPartySaveData>,
}

impl Round1 {
    pub fn new(
        params: Arc<Parameters>,
        save: Arc<Mutex<LocalPartySaveData>>,
        temp: Arc<Mutex<LocalTempData>>,
        out_ch: Sender<Box<dyn TssMessage + Send>>,
        end_ch: Sender<LocalPartySaveData>,
    ) -> Self {
        let base = BaseRound::new(1, params.party_count());
        Self {
            base,
            params,
            save,
            temp,
            out_ch,
            end_ch,
        }
    }

    /// Generates the SSID (Session Shared ID) for the protocol execution.
    /// SSID = (sid, P1_id, ..., Pn_id)
    fn get_ssid(&self) -> Result<Vec<u8>, RoundError> {
        let party_ids = self.params.parties().party_ids();
        let mut string_ids: Vec<&str> = party_ids.iter().map(|p| p.id.as_str()).collect();
        string_ids.sort(); // Ensure consistent order

        // Use a fixed session ID prefix or allow it to be passed in parameters
        let sid = "tss-lib-keygen-session"; // Example Session ID

        let mut data_to_hash = sid.as_bytes().to_vec();
        for id_str in string_ids {
            data_to_hash.extend_from_slice(id_str.as_bytes());
        }
        // Include nonce from temp data
         let temp_data = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![]))?;
         let nonce = temp_data.ssid_nonce.as_ref().ok_or_else(|| self.wrap_error(anyhow!("SSID nonce not set"), vec![]))?;
         data_to_hash.extend_from_slice(&nonce.to_bytes_be().1);

         // TODO: Replace with a proper H' function if specified, otherwise SHA256 is a reasonable default.
         use sha2::{{Sha256, Digest}};
         let hash = Sha256::digest(&data_to_hash);
         Ok(hash.to_vec())
    }
}

impl Round for Round1 {
    fn params(&self) -> &Parameters {
        &self.params
    }

    fn round_number(&self) -> i32 {
        self.base.round_number()
    }

    fn start(&self) -> Result<(), RoundError> {
        if self.base.started() {
            return Err(self.wrap_error(anyhow!("Round 1 already started"), vec![]));
        }
        self.base.set_started();
        self.base.reset_ok(); // Reset ok vector for this round

        let current_party_id = self.params.party_id();
        let i = current_party_id.index;

         info!(target: "tss-lib", party_id = ?current_party_id, "Keygen Round 1 starting: Generating VSS shares and commitments");

        // 1. Calculate "partial" key share ui
        let ec_order = self.params.ec().order();
        // TODO: Use the specific RNG from params if implemented
        let mut rng = thread_rng();
        let ui = get_random_positive_int(&mut rng, &ec_order)
            .ok_or_else(|| self.wrap_error(anyhow!("Failed to generate random ui"), vec![current_party_id.as_ref().clone()]))?;

        {
             let mut temp_data_lock = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;
            temp_data_lock.ui = Some(ui.clone()); // Store ui temporarily
        }

        // 2. Compute the VSS shares
        let threshold = self.params.threshold();
        let all_party_keys: Vec<BigInt> = self.params.parties().party_ids().iter().map(|p| p.key.clone()).collect();
        let (vs, shares) = vss::FeldmanVssScheme::create(
            self.params.ec(),
            threshold,
            &ui,
            &all_party_keys,
            &mut rng, // Use proper RNG from params eventually
        ).map_err(|e| self.wrap_error(e, vec![current_party_id.as_ref().clone()]))?;

        {
            let mut save_data_lock = self.save.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock save data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             save_data_lock.ks = all_party_keys; // Store all keys
             save_data_lock.share_id = current_party_id.key.clone(); // Store this party's key as ShareID
        }

        // 3. Make commitment C_i = H(V_i0, ..., V_it)
        let vss_commitment_points = vs.commitments().clone(); // Get the commitment points [G*u_i, G*a_i1, ...]
        let (commitment, decommitment) = HashCommitment::create_commitment(&mut rng, &vss_commitment_points)?; // Commit to the points

        // 4-11. Generate Paillier keys, safe primes, Ntilde, H1, H2, and DLN proofs
        let pre_params = {
            let mut save_data_lock = self.save.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock save data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             if save_data_lock.local_pre_params.validate_with_proof() {
                 debug!(target: "tss-lib", party_id = ?current_party_id, "Using pre-computed Paillier params");
                 save_data_lock.local_pre_params.clone()
            } else {
                 debug!(target: "tss-lib", party_id = ?current_party_id, "Generating new Paillier params...");
                // TODO: Implement context/timeout and concurrency properly
                let new_pre_params = LocalPreParams::generate_pre_params(
                    self.params.safe_prime_gen_timeout(),
                     // self.params.concurrency(), // Need a way to pass concurrency
                 ).map_err(|e| self.wrap_error(e, vec![current_party_id.as_ref().clone()]))?;
                 info!(target: "tss-lib", party_id = ?current_party_id, "Finished generating Paillier params");
                 save_data_lock.local_pre_params = new_pre_params.clone(); // Save generated params
                 new_pre_params
            }
        };

        // Generate DLN proofs for Ntilde_i = p_i * q_i
         let dln_proof1 = dlnproof::Proof::new(
             &pre_params.h1i,
             &pre_params.h2i,
             &pre_params.alpha, // secret
             &pre_params.p,     // p'
             &pre_params.q,     // q'
             &pre_params.ntilde_i,
             &mut rng,          // Use proper RNG
         ).map_err(|e| self.wrap_error(e, vec![current_party_id.as_ref().clone()]))?;
         let dln_proof2 = dlnproof::Proof::new(
             &pre_params.h2i,
             &pre_params.h1i,
             &pre_params.beta, // secret
             &pre_params.p,
             &pre_params.q,
             &pre_params.ntilde_i,
             &mut rng,
         ).map_err(|e| self.wrap_error(e, vec![current_party_id.as_ref().clone()]))?;

        // Save/update temp and save data
        {
            let mut temp_data_lock = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             let mut save_data_lock = self.save.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock save data: {}", e), vec![current_party_id.as_ref().clone()]))?;

            // Temp data
             temp_data_lock.ssid_nonce = Some(BigInt::zero()); // Initialize nonce for SSID calc
             temp_data_lock.vs = Some(vs); // VSS scheme
             temp_data_lock.shares = Some(shares); // Our shares
             temp_data_lock.decommit_poly_g = Some(decommitment); // Decommitment C_i

            // Save data
             save_data_lock.ntilde_j[i as usize] = Some(pre_params.ntilde_i.clone());
             save_data_lock.h1j[i as usize] = Some(pre_params.h1i.clone());
             save_data_lock.h2j[i as usize] = Some(pre_params.h2i.clone());
             save_data_lock.paillier_pks[i as usize] = Some(pre_params.paillier_sk.public_key().clone());
             save_data_lock.paillier_sk = Some(pre_params.paillier_sk); // Store private key

            // Calculate SSID
             let ssid = self.get_ssid()?; // Must be called after nonce is set
             temp_data_lock.ssid = Some(ssid);
        }

        // BROADCAST commitments, paillier pk + proof; round 1 message
         let round1_msg = KGRound1Message::new(
             commitment, // C_i
             pre_params.paillier_sk.public_key(), // Paillier PK_i
             pre_params.ntilde_i, // Ntilde_i
             pre_params.h1i,
             pre_params.h2i,
             dln_proof1,
             dln_proof2,
         );

         // Create routing info for broadcast
         let routing = MessageRoutingInfo {
             from: current_party_id.as_ref().clone(),
             to: None, // Broadcast
             is_broadcast: true,
             is_to_old_committee: false,
             is_to_old_and_new_committees: false,
         };

         let tss_msg = crate::tss::message::ParsedMessageImpl::from_content(routing, &round1_msg)?;

         // Store own message
         {
             let mut temp_data_lock = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;
             temp_data_lock.message_store.kg_round1_messages.insert(i, Arc::new(tss_msg.clone())); // Store Arc
         }

         // Send message
         self.out_ch.send(Box::new(tss_msg))
             .map_err(|e| self.wrap_error(anyhow!("Failed to send Round1 message: {}", e), vec![]))?;

        info!(target: "tss-lib", party_id = ?current_party_id, "Keygen Round 1 finished successfully");
        Ok(())
    }

    fn can_accept(&self, msg: &dyn ParsedMessage) -> bool {
        msg.is_broadcast() && msg.type_url() == KGRound1Message::TYPE_URL
    }

    fn update(&self) -> Result<bool, RoundError> {
        let mut all_ok = true;
        let required_count = self.params().party_count(); // All parties must send in R1

        let temp_data = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![]))?;

        for j in 0..required_count {
            if self.base.is_ok(j) { continue; }
            if temp_data.message_store.kg_round1_messages.contains_key(&(j as i32)) {
                self.base.set_ok(j);
            } else {
                all_ok = false;
            }
        }
         debug!(target: "tss-lib", party_id = ?self.params.party_id(), ok_parties = ?self.base.get_ok_vec(), "Round 1 update check");
        Ok(all_ok)
    }

    fn next_round(&self) -> Option<Arc<dyn Round>> {
        self.base.set_started_unwrapped(); // Mark finished
         Some(Arc::new(Round2::new(
            self.params.clone(),
            self.save.clone(),
            self.temp.clone(),
            self.out_ch.clone(),
            self.end_ch.clone(),
        )))
    }

    // Waiting for all parties in R1
    fn waiting_for(&self) -> Vec<PartyID> {
        let party_ids = self.params.parties().party_ids();
        self.base.waiting_for(party_ids)
    }
} 