// Base struct for common party logic in EDDSA keygen rounds

use std::sync::{Arc, Mutex, mpsc::Sender};
use std::error::Error as StdError;

// Keygen specific imports
use crate::eddsa::keygen::Parameters;
use crate::eddsa::keygen::local_party::{KeygenPartyTempData, KeygenPartySaveData};
use crate::eddsa::keygen::error::TssError as KeygenTssError;
use crate::eddsa::keygen::rounds::PROTOCOL_NAME;

// TSS core imports
use crate::tss::party_id::{PartyID, SortedPartyIDs};
use crate::tss::message::{TssMessage, MessageContent, MessageWrapper}; // Use tss::message

// Crypto imports
use prost::Message; // For MessageContent constraint and encoding

#[derive(Debug)] // Add Debug derive
pub struct BaseParty {
    pub(crate) params: Arc<Parameters>,
    pub(crate) temp_data: Arc<Mutex<KeygenPartyTempData>>,
    pub(crate) save_data: Arc<Mutex<KeygenPartySaveData>>,
    pub(crate) out_channel: Sender<TssMessage>,
    pub(crate) end_channel: Option<Sender<KeygenPartySaveData>>, // Optional: only needed for final round

    pub(crate) round_number: u32,
    pub(crate) started: bool,
    pub(crate) ok: Vec<bool>, // Received message flags
    // TODO: Add message_store if BaseParty should manage raw message storage
    // pub(crate) message_store: MessageStore, // Needs definition
}

// Add implementation block
impl BaseParty {
    pub fn new(
        params: Arc<Parameters>,
        temp_data: Arc<Mutex<KeygenPartyTempData>>,
        save_data: Arc<Mutex<KeygenPartySaveData>>,
        out_channel: Sender<TssMessage>,
        round_number: u32,
    ) -> Self {
        let party_count = params.party_count();
        Self {
            params,
            temp_data,
            save_data,
            out_channel,
            end_channel: None, // Initialize as None, can be set later
            round_number,
            started: false,
            ok: vec![false; party_count], // Initialize based on party count
        }
    }

    // Method to add the end channel (used in LocalParty::new)
    pub fn with_end_channel(mut self, end_channel: Sender<KeygenPartySaveData>) -> Self {
        self.end_channel = Some(end_channel);
        self
    }

    // --- Helper Methods --- //

    pub fn params(&self) -> &Arc<Parameters> {
        &self.params
    }

    // Provides direct access to temp data mutex guard
    pub fn temp(&self) -> std::sync::MutexGuard<'_, KeygenPartyTempData> {
        self.temp_data.lock().expect("Failed to lock temp data mutex in BaseParty")
    }

    // Provides direct access to save data mutex guard
    pub fn save(&self) -> std::sync::MutexGuard<'_, KeygenPartySaveData> {
        self.save_data.lock().expect("Failed to lock save data mutex in BaseParty")
    }

     // Provides mutable access to save data mutex guard
    pub fn save_mut(&self) -> std::sync::MutexGuard<'_, KeygenPartySaveData> {
        self.save_data.lock().expect("Failed to lock save data mutex (mut) in BaseParty")
    }

    pub fn party_id(&self) -> &PartyID {
        self.params.party_id()
    }

    pub fn party_count(&self) -> usize {
        self.params.party_count()
    }

    // Returns this party's index in the sorted list
    pub fn party_index(&self) -> usize {
        self.params.party_index().expect("Party index not found in BaseParty")
    }

    // Generic error wrapping function - returns keygen::TssError
    pub fn wrap_error(&self, err: Box<dyn StdError + Send + Sync + 'static>, culprits: Vec<PartyID>) -> KeygenTssError {
        // Use the TssError::new_round_error helper defined in keygen::error
        KeygenTssError::new_round_error(
            err,
            self.round_number,
            culprits,
        )
    }

    // Convenience wrapper for base errors not specific to a round - returns keygen::TssError
    pub fn wrap_base_error(&self, message: String) -> KeygenTssError {
         // Use the BaseError variant of the keygen::TssError enum
         KeygenTssError::BaseError { message }
    }

    // --- Message Tracking Methods --- //

    // Reset the message received flags for the start of a round
    pub fn reset_ok(&mut self) {
        for i in 0..self.party_count() {
            self.ok[i] = false;
        }
    }

    // Mark a message as received from a party
    pub fn set_ok(&mut self, party_index: usize) -> Result<(), KeygenTssError> {
        if party_index >= self.party_count() {
            return Err(self.wrap_base_error(format!("set_ok index out of bounds: {}", party_index)));
        }
        self.ok[party_index] = true;
        Ok(())
    }

    // Return a list of parties from whom messages are still expected
    pub fn waiting_for(&self) -> Vec<PartyID> {
        let mut waiting_list = Vec::new();
        let parties = self.params.parties(); // Get Arc<SortedPartyIDs>
        for i in 0..self.party_count() {
            if !self.ok[i] {
                // Find the PartyID corresponding to index i
                if let Some(party_id) = parties.get(i) {
                    waiting_list.push(party_id.clone());
                }
                // Else: Log error? Index should always be valid if ok has correct size.
            }
        }
        waiting_list
    }

     // Simple count of received messages (may not be sufficient for rounds needing multiple message types)
    pub fn message_count(&self) -> usize {
        self.ok.iter().filter(|&&ok_flag| ok_flag).count()
    }

    // --- Message Creation/Sending Methods --- //

    // Creates a MessageWrapper for P2P send
    fn new_p2p_message(
        &self,
        to: &PartyID,
        content: Box<dyn MessageContent>,
    ) -> Result<MessageWrapper, KeygenTssError> {
        Ok(MessageWrapper::new(
            false, // is_broadcast
            false, // is_to_old_committee
            false, // is_to_old_and_new_committees
            self.party_id().clone(),
            vec![to.clone()],
            content,
        ))
    }

    // Creates a MessageWrapper for broadcast
    fn new_broadcast_message(
        &self,
        content: Box<dyn MessageContent>,
    ) -> Result<MessageWrapper, KeygenTssError> {
        // Determine broadcast recipients (all other parties)
        let recipients = self.params.parties().iter()
            .filter(|p| p != self.party_id())
            .cloned()
            .collect();

        Ok(MessageWrapper::new(
            true, // is_broadcast
            false, // is_to_old_committee
            false, // is_to_old_and_new_committees
            self.party_id().clone(),
            recipients,
            content,
        ))
    }

    // Sends a P2P message
    pub fn send_p2p(&self, msg: MessageWrapper) -> Result<(), KeygenTssError> {
        // Validation might happen within MessageWrapper::new or sending logic
        // TODO: Update channel to accept MessageWrapper or serialize it
        // Temporary: Convert wrapper to placeholder TssMessage for channel
        let temp_msg = TssMessage {
            payload: msg.message.encode_to_vec(), // Re-encode content
            from: msg.from.clone(),
            to: Some(msg.to().clone()),
            is_broadcast: false,
        };
        self.out_channel.send(temp_msg)
            .map_err(|e| self.wrap_base_error(format!("Failed to send P2P message: {}", e)))
    }

    // Sends a broadcast message
    pub fn send_broadcast(&self, msg: MessageWrapper) -> Result<(), KeygenTssError> {
        // TODO: Update channel to accept MessageWrapper or serialize it
        // Temporary: Convert wrapper to placeholder TssMessage for channel
        let temp_msg = TssMessage {
            payload: msg.message.encode_to_vec(), // Re-encode content
            from: msg.from.clone(),
            to: None, // Broadcast might imply None for receiver
            is_broadcast: true,
        };
        self.out_channel.send(temp_msg)
             .map_err(|e| self.wrap_base_error(format!("Failed to send broadcast message: {}", e)))
    }

     // Sends the final save data through the end channel
    pub fn send_complete_signal(&self, save_data: KeygenPartySaveData) -> Result<(), KeygenTssError> {
        if let Some(end_ch) = &self.end_channel {
            end_ch.send(save_data)
                  .map_err(|e| self.wrap_base_error(format!("Failed to send completion signal: {}", e)))
        } else {
            Err(self.wrap_base_error("End channel not configured for this party".to_string()))
        }
    }

    // TODO: Add store_message method if BaseParty needs to manage received message state
    // pub fn store_message(&mut self, msg: ParsedMessage) -> Result<(), TssError> { ... }
}

// Removed placeholder TssMessage definition
/*
#[derive(Debug, Clone)]
pub struct TssMessage {
    pub payload: Vec<u8>,
    pub from: PartyID,
    pub to: Option<Vec<PartyID>>,
    pub is_broadcast: bool,
}
*/

// ... (Required imports for the edits) 