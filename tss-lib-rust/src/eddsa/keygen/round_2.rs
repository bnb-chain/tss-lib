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
        // Implement the logic for starting Round 2
        // This may involve processing messages from Round 1 and preparing for Round 3
        Ok(())
    }

    pub fn can_accept(&self, _msg: &KGRound2Message1) -> bool {
        // Implement logic to check if a message can be accepted in Round 2
        true
    }

    pub fn update(&mut self) -> Result<bool, String> {
        // Implement the update logic for Round 2
        // This may involve checking received messages and updating state
        Ok(true)
    }

    pub fn next_round(self) -> Result<(), String> {
        // Implement transition to the next round if applicable
        Ok(())
    }
}
