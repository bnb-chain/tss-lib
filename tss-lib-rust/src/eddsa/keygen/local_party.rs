// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Implements tss::Party
// Implements Display

use std::fmt;
use std::sync::mpsc::Sender;
use num_bigint::BigInt;
use crate::eddsa::keygen::messages::{KeygenMessageEnum, KGRound1Message, KGRound2Message1, KGRound2Message2, KGRound3Message, parse_message_from_payload};
use crate::eddsa::keygen::save_data::LocalPartySaveData;
use crate::crypto::commitments::{HashCommitment, HashDeCommitment};
use crate::crypto::vss::VssShare as GenericVssShare; // Assuming a generic VssShare struct

// --- TSS Core Imports ---
use crate::tss::{
    party_id::{PartyID, SortedPartyIDs},
    error::TssError,
    // Import the placeholder TssMessage from party_base for now
    // message::{Message as TssMessage, ParsedMessage, MessageRouting},
    // Use tss::Party trait, but tss::Round and tss::BaseParty are replaced by keygen versions
    party::{Party as TssParty, Round as TssRound},
};
// --- End TSS Core Imports ---

// --- Keygen Specific Imports ---
use crate::eddsa::keygen::Parameters;
use crate::eddsa::keygen::BaseParty; // Import keygen::BaseParty
use crate::eddsa::keygen::party_base::TssMessage; // Use placeholder TssMessage from party_base
use crate::eddsa::keygen::messages::{KGRound1Message, KGRound2Message1, KGRound2Message2, parse_message_from_payload};
use crate::eddsa::keygen::round_1::Round1; // Import Round1 for party initialization
use crate::eddsa::keygen::save_data::LocalPartySaveData as KeygenPartySaveData; // Use concrete save data
use crate::eddsa::keygen::local_party::KeygenPartyTempData; // Use concrete temp data
use crate::eddsa::keygen::TssError; // Import keygen::TssError
use crate::eddsa::keygen::rounds::KeygenRound; // Import the keygen trait
use crate::tss::wire; // For parsing
// --- End Keygen Specific Imports ---

use std::collections::HashMap;
use num_bigint::BigInt;
use crate::tss::message::{ParsedMessage, MessageRouting, MessageContent}; // Use tss structs
use crate::tss::wire; // Import wire helpers

// Use KeygenPartyTempData defined here
#[derive(Clone, Debug)]
pub struct KeygenPartyTempData {
    // ... (fields as before)
}
impl KeygenPartyTempData {
    // ... (new method as before)
}

// Removed KeygenPartySaveData definition - use the one from save_data.rs
// #[derive(Clone, Debug)] pub struct KeygenPartySaveData { ... }
// impl KeygenPartySaveData { ... }


pub struct LocalParty {
    pub params: Arc<Parameters>,
    pub temp: Arc<Mutex<KeygenPartyTempData>>,
    pub data: Arc<Mutex<KeygenPartySaveData>>,
    base: BaseParty,
    // Add field to hold the current round
    current_round: Option<Box<dyn KeygenRound>>,
}

impl LocalParty {
    pub fn new(
        params: Parameters,
        out_channel: Sender<TssMessage>,
        end_channel: Sender<KeygenPartySaveData>,
    ) -> Result<Self, TssError> {
        let party_id = params.party_id().clone();
        let party_count = params.party_count();
        let parties = params.parties().clone();
        let threshold = params.threshold();

        // Initialize save data (assuming new_empty exists in save_data.rs)
        let data = KeygenPartySaveData::new_empty(party_count);
        let temp = KeygenPartyTempData::new(party_count);

        let shared_params = Arc::new(params);
        let shared_temp = Arc::new(Mutex::new(temp));
        let shared_data = Arc::new(Mutex::new(data));

        // Create first round
        let first_round = Round1::new(
            shared_params.clone(),
            shared_data.clone(),
            shared_temp.clone(),
            out_channel.clone(), // Clone for round
            end_channel.clone(),   // Clone for round
        );

        // Initialize BaseParty (no longer holds the round)
        let base = BaseParty::new(
            shared_params.clone(),
            shared_temp.clone(),
            shared_data.clone(),
            out_channel,
            1, // Starting round number
        ).with_end_channel(end_channel);

        Ok(Self {
            params: shared_params,
            temp: shared_temp,
            data: shared_data,
            base,
            current_round: Some(first_round), // Initialize with Round 1
        })
    }

    // Public start method
    pub fn start(&mut self) -> Result<(), TssError> {
        if let Some(round) = self.current_round.as_mut() {
            round.start()
        } else {
            Err(TssError::BaseError{ message: "Party already finished".to_string() })
        }
    }

    // Public update method
    pub fn update_from_bytes(&mut self, wire_bytes: &[u8], from: &PartyID, is_broadcast: bool) -> Result<(), TssError> {
        // Get current round reference
        let current_round_num = self.current_round.as_ref().map(|r| r.round_number()).unwrap_or(0);
        if current_round_num == 0 {
            return Err(TssError::BaseError{ message: "Cannot update party that is not running".to_string() });
        }

        // 1. Parse message (using tss::wire, expect panic for now)
        let parsed_msg = wire::parse_msg(wire_bytes, from, is_broadcast)
            .map_err(|e| self.base.wrap_base_error(format!("Wire parse error: {}", e)))?;

        // Check if message is for the current round
        // TODO: Need round info from parsed_msg or wire protocol
        // if parsed_msg.round_number() != current_round_num { ... error ... }

        // 2. Validate sender
        self.validate_message_sender(&parsed_msg)?; // Call helper

        // 3. Store message via the current round
        if let Some(round) = self.current_round.as_mut() {
            // store_message should validate content type and call base.set_ok
            round.store_message(parsed_msg)?;

            // 4. Check if we can proceed
            if round.can_proceed() {
                round.proceed()?; // Perform round logic

                // 5. Advance to next round
                // Take ownership of the current round Box to call next_round
                if let Some(finished_round) = self.current_round.take() {
                    self.current_round = finished_round.next_round();
                    // Start the new round immediately if it exists
                    if let Some(new_round) = self.current_round.as_mut() {
                        new_round.start()?;
                    }
                } else {
                    // Should not happen if we just took it
                    return Err(TssError::InternalError{ message: "Failed to take ownership of round for advancing".to_string() });
                }
            }
        } else {
            // Party finished, but received another message?
            return Err(TssError::BaseError{ message: "Received message after party finished".to_string() });
        }
        Ok(())
    }

    // Helper for validating message sender (subset of old validate_message)
    fn validate_message_sender(&self, msg: &ParsedMessage) -> Result<(), TssError> {
        let from_id = msg.from();
        if self.params.parties().find_by_id(from_id).is_none() {
            return Err(TssError::BaseError{ message: format!("Sender not found: {:?}", from_id) });
        }
        let max_from_idx = self.base.party_count() - 1;
        if from_id.index() > max_from_idx {
             return Err(TssError::InvalidPartyIndex {
                 received_index: from_id.index(),
                 max_index: max_from_idx,
             });
        }
        Ok(())
    }

    // Optional: Public methods to check state
    pub fn running(&self) -> bool {
        self.current_round.is_some()
    }

    pub fn waiting_for(&self) -> Option<Vec<PartyID>> {
         self.current_round.as_ref().map(|r| r.base().waiting_for())
    }

    pub fn round_number(&self) -> Option<u32> {
        self.current_round.as_ref().map(|r| r.round_number())
    }
}

impl fmt::Display for LocalParty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         // Use {} for PartyID now that Display is implemented
         // Keep {:?} for BaseParty as it only derives Debug
         write!(f, "id: {}, base: {:?}", self.party_id(), self.base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tss::generate_test_party_ids;
    use crate::tss::new_peer_context;
    use crate::tss::curve::CurveName; // Import CurveName
    use std::sync::mpsc::channel;

    // Helper uses keygen::Parameters
    fn create_test_params(id_str: &str, index: usize, party_count: usize, threshold: usize) -> Parameters {
        // ... (implementation as before)
        Parameters::new(
             CurveName::Ed25519,
             p2p_ctx,
             party_id,
             parties,
             threshold
        )
    }

     #[test]
     fn test_local_party_new_success() {
         let party_count = 3;
         let threshold = 1;
         let params = create_test_params("p1", 0, party_count, threshold);
         let (out_tx, _) = channel();
         let (end_tx, _) = channel();

         let party_result = LocalParty::new(params, out_tx, end_tx);

         assert!(party_result.is_ok());
         let party = party_result.unwrap();
         assert_eq!(party.base.party_count(), party_count); // Check via base
         assert_eq!(party.base.params().threshold(), threshold); // Check via base
         // Check save data init (needs access method or field on BaseParty/SaveData)
         // assert!(!party.base.save().started);
         assert_eq!(party.base.temp().kgcs.len(), party_count); // Check temp via base
     }
}

// Removed placeholder KeygenMessageEnum
/*
#[derive(Debug)]
enum KeygenMessageEnum {
    Round1(KGRound1Message),
    Round2_1(KGRound2Message1),
    Round2_2(KGRound2Message2),
}
*/

// Removed placeholder ParsedMessage definition
/*
#[derive(Debug, Clone)]
pub struct ParsedMessage { pub dummy: u8 }
*/

#[cfg(test)]
mod keygen_integration_tests {
    // ... (imports - use TssParty trait)
    use crate::tss::{generate_test_party_ids, new_peer_context, party::TssParty};
    // ... (other imports)
    use crate::eddsa::keygen::party_base::TssMessage; // Use placeholder TssMessage
    use crate::eddsa::keygen::save_data::LocalPartySaveData as KeygenPartySaveData;
    use select::select; // Use crossbeam select!

    // ... (test_e2e_keygen_concurrent)
    #[test]
    fn test_e2e_keygen_concurrent() {
        // ... (setup as before, uses keygen::Parameters)

        // Start key generation in separate threads
        let handles: Vec<_> = parties.into_iter().map(|mut party| {
            thread::spawn(move || {
                // TODO: Update start call when implemented
                // party.start().expect("Party start failed");
                party // Return the party
            })
        }).collect();

        // ... (Message routing simulation)
        let router_handle = thread::spawn({
            // ... (closures capturing Arcs)
            move || {
                loop {
                    // ... (check active_parties)
                    select! { // Use crossbeam select!
                        recv(out_receiver) -> msg_result => {
                            if let Ok(tss_msg) = msg_result {
                                // TODO: Refactor party access and update call
                                // Need mutable access to parties vec
                                // let dest_indices = ... ;
                                // for dest_idx in dest_indices {
                                //     parties[dest_idx].update_from_bytes(...).unwrap();
                                // }
                                println!("Router received message: {:?}", tss_msg); // Placeholder
                            } else {
                                println!("Outgoing channel closed unexpectedly.");
                                break;
                            }
                        },
                        recv(end_receiver) -> data_result => {
                            if let Ok(save_data) = data_result {
                                // TODO: Ensure save_data has original_index or equivalent
                                // let party_idx = save_data.original_index().unwrap();
                                let party_idx = 0; // Placeholder
                                final_party_data.lock().unwrap()[party_idx] = Some(save_data);
                                active_parties.fetch_sub(1, Ordering::SeqCst);
                                println!("Router received final data from party {}", party_idx);
                            } else {
                                println!("Ending channel closed unexpectedly.");
                                break;
                            }
                        },
                        // default(Duration::from_secs(60)) => { // Optional timeout
                        //     panic!("Test timed out");
                        // }
                    }
                }
                println!("Message router finished.");
            }
        });

        // ... (wait for handles)

        // Assertions
        let final_data_guard = final_party_data.lock().unwrap();
        assert_eq!(final_data_guard.len(), party_count, "Expected {} final save data items", party_count);
        assert!(final_data_guard.iter().all(|opt| opt.is_some()), "Not all parties finished and saved data");

        let first_data = final_data_guard[0].as_ref().unwrap();
        // Assuming eddsa_pub field exists on KeygenPartySaveData from save_data.rs
        let final_pk = first_data.eddsa_pub.expect("Missing final public key");

        // ... (Other assertions remain, commented out due to missing VSS/scalar ops)

        println!("E2E Keygen test completed successfully.");
    }
}
