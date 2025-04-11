// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/ecdsa/keygen/round_4.go

use crate::{
    common::task_name::TASK_NAME,
    protocols::ecdsa::keygen::{
        types::{LocalPartySaveData, LocalTempData},
        messages::{KGRound3Message},
        rounds::paillier_proof_verifier::{PaillierProofVerifier, PaillierProofVerifierContext, PaillierProofVerificationResult},
    },
    tss::{
        message::{TssMessage, ParsedMessage},
        round::{Round, RoundError, RoundErr, BaseRound},
        params::Parameters,
        party_id::PartyID,
    },
};

use std::{{
    sync::{Arc, Mutex, mpsc::Sender},
}};
use log::{info, debug, error};
use anyhow::{Result, anyhow};
use std::collections::HashMap;

pub struct Round4 {
    base: BaseRound,
    params: Arc<Parameters>,
    save: Arc<Mutex<LocalPartySaveData>>,
    temp: Arc<Mutex<LocalTempData>>,
    out_ch: Sender<Box<dyn TssMessage + Send>>,
    end_ch: Sender<LocalPartySaveData>,
}

impl Round4 {
    pub fn new(
        params: Arc<Parameters>,
        save: Arc<Mutex<LocalPartySaveData>>,
        temp: Arc<Mutex<LocalTempData>>,
        out_ch: Sender<Box<dyn TssMessage + Send>>,
        end_ch: Sender<LocalPartySaveData>,
    ) -> Self {
        let base = BaseRound::new(4, params.party_count());
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

impl Round for Round4 {
    fn params(&self) -> &Parameters {
        &self.params
    }

    fn round_number(&self) -> i32 {
        self.base.round_number()
    }

    fn start(&self) -> Result<(), RoundError> {
        if self.base.started() {
            return Err(self.wrap_error(anyhow!("Round 4 already started"), vec![]));
        }
        self.base.set_started();
        self.base.reset_ok(); // Though not strictly needed as we don't wait for messages

        let current_party_id = self.params.party_id();
        let i_usize = current_party_id.index as usize;

         info!(target: "tss-lib", party_id = ?current_party_id, "Keygen Round 4 starting: Verifying Paillier proofs");

        // 1-3. Verify Paillier proofs concurrently
        let paillier_contexts: Vec<PaillierProofVerifierContext> = {
            let temp_data_lock = self.temp.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock temp data: {}", e), vec![current_party_id.as_ref().clone()]))?;
            let save_data_lock = self.save.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock save data: {}", e), vec![current_party_id.as_ref().clone()]))?;

            let ecdsa_pub_key = save_data_lock.ecdsa_pub.as_ref()
                .ok_or_else(|| self.wrap_error(anyhow!("Missing ECDSA PubKey"), vec![current_party_id.as_ref().clone()]))?;

             temp_data_lock.message_store.kg_round3_messages.iter().filter_map(|(j_idx, msg_arc)| {
                 let j = *j_idx as usize;
                 if j == i_usize { return None; } // Skip self

                 // Should be safe to unwrap
                 let r3_msg = msg_arc.M::<KGRound3Message>().unwrap();
                 let paillier_pk_j = save_data_lock.paillier_pks[j].clone()
                     .ok_or_else(|| self.wrap_error(anyhow!("Missing Paillier PK for party {}", j), vec![self.params.parties().party_ids()[j].as_ref().clone()]))
                     .ok()?; // Use ok() to fit into filter_map
                 let party_id_j = self.params.parties().party_ids()[j].clone(); // Arc clone

                 Some(PaillierProofVerifierContext {
                     paillier_pk: paillier_pk_j,
                     proof: r3_msg.paillier_proof,
                     associated_party_id: party_id_j,
                     verifier_ecdsa_pk_bytes: ecdsa_pub_key.to_bytes(true), // Compressed pubkey bytes
                 })
            }).collect()
        };

         debug!(target: "tss-lib", party_id = ?current_party_id, concurrency = self.params.concurrency(), "Setting up Paillier proof verification");
        let paillier_verifier = PaillierProofVerifier::new(self.params.concurrency());
        for context in paillier_contexts {
            paillier_verifier.verify_paillier_proof(context);
        }
        let paillier_results = paillier_verifier.collect_results(self.params.party_count() - 1);

         // Check results
         let mut culprits = Vec::new();
         self.base.set_ok(i_usize); // Mark self as OK
         for result in paillier_results {
             if result.is_valid {
                 self.base.set_ok(result.party_id.index as usize);
                 debug!(target: "tss-lib", party_id = ?current_party_id, verified_party = ?result.party_id, "Paillier proof verified");
             } else {
                 error!(target: "tss-lib", party_id = ?current_party_id, culprit = ?result.party_id, "Paillier proof verification failed");
                 culprits.push(result.party_id.as_ref().clone());
             }
         }

         if !culprits.is_empty() {
             return Err(self.wrap_error(anyhow!("Paillier proof verification failed"), culprits));
         }

        // Send final save data to the application layer channel
         info!(target: "tss-lib", party_id = ?current_party_id, "Keygen Round 4 finished successfully, sending result.");
        let final_save_data = {
            let save_data_lock = self.save.lock().map_err(|e| self.wrap_error(anyhow!("Failed to lock save data: {}", e), vec![current_party_id.as_ref().clone()]))?;
            save_data_lock.clone()
        };

         self.end_ch.send(final_save_data)
            .map_err(|e| self.wrap_error(anyhow!("Failed to send final save data: {}", e), vec![]))?;

        self.base.set_started_unwrapped(); // Mark finished *after* sending
        Ok(())
    }

    fn can_accept(&self, _msg: &dyn ParsedMessage) -> bool {
        // No messages expected in this round
        false
    }

    fn update(&self) -> Result<bool, RoundError> {
        // No messages expected, update always returns false
        Ok(false)
    }

    fn next_round(&self) -> Option<Arc<dyn Round>> {
        None // This is the final round
    }

    // Waiting for no one in R4 (verification happens in start)
     fn waiting_for(&self) -> Vec<PartyID> {
         Vec::new()
     }
} 