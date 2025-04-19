use crate::eddsa::keygen::round_1::Round1;
use crate::eddsa::keygen::messages::{KGRound2Message1, KGRound2Message2};
use crate::eddsa::keygen::local_party::{LocalTempData, LocalMessageStore};
use crate::tss::params::Parameters;
use crate::tss::party_id::PartyID;
use num_bigint::BigInt;

pub struct Round2<'a> {
    pub round1: Round1<'a>,
}

impl<'a> Round2<'a> {
    pub fn new(round1: Round1<'a>) -> Self {
        Round2 { round1 }
    }

    pub fn start(&mut self) -> Result<(), String> {
        // Process messages from Round 1
        for (i, msg) in self.round1.base.temp.local_message_store.kg_round1_messages.iter().enumerate() {
            if let Some(msg) = msg {
                // Process each message
                // Example: Verify commitments, calculate shares, etc.
                // self.round1.base.temp.shares[i] = Some(processed_share);
            }
        }
        // Prepare for Round 3
        // Example: Generate new commitments or shares
        Ok(())
    }

    pub fn can_accept(&self, _msg: &KGRound2Message1) -> bool {
        // Check if the message is valid for Round 2
        // Example: Check message type, sender, etc.
        // return self.round1.base.params.is_valid_message(msg);
        true // Placeholder
    }

    pub fn update(&mut self) -> Result<bool, String> {
        // Update state based on received messages
        let mut all_messages_received = true;
        for msg in &self.round1.base.temp.local_message_store.kg_round2_message1s {
            if msg.is_none() {
                all_messages_received = false;
                break;
            }
        }
        Ok(all_messages_received)
    }

    pub fn next_round(self) -> Result<(), String> {
        // Implement transition to the next round if applicable
        Ok(())
    }
}
