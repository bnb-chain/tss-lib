use std::sync::{Arc, Mutex};

pub trait Round {
    fn start(&self) -> Result<(), Error>;
    fn update(&self) -> Result<(), Error>;
    fn can_proceed(&self) -> bool;
    fn next_round(&self) -> Box<dyn Round>;
    fn waiting_for(&self) -> Vec<PartyID>;
    fn wrap_error(&self, err: Box<dyn std::error::Error>, culprits: Vec<PartyID>) -> Error;
    fn params(&self) -> &Parameters;
    fn round_number(&self) -> u32;
}

pub trait Party {
    fn start(&self) -> Result<(), Error>;
    fn update_from_bytes(&self, wire_bytes: &[u8], from: &PartyID, is_broadcast: bool) -> Result<bool, Error>;
    fn update(&self, msg: ParsedMessage) -> Result<bool, Error>;
    fn running(&self) -> bool;
    fn waiting_for(&self) -> Vec<PartyID>;
    fn validate_message(&self, msg: ParsedMessage) -> Result<bool, Error>;
    fn store_message(&self, msg: ParsedMessage) -> Result<bool, Error>;
    fn first_round(&self) -> Box<dyn Round>;
    fn wrap_error(&self, err: Box<dyn std::error::Error>, culprits: Vec<PartyID>) -> Error;
    fn party_id(&self) -> PartyID;
}

pub struct BaseParty {
    mtx: Arc<Mutex<()>>,
    rnd: Option<Box<dyn Round>>,
    first_round: Box<dyn Round>,
}

impl BaseParty {
    pub fn new(first_round: Box<dyn Round>) -> Self {
        BaseParty {
            mtx: Arc::new(Mutex::new(())),
            rnd: None,
            first_round,
        }
    }

    pub fn running(&self) -> bool {
        self.rnd.is_some()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    struct TestRound;

    impl Round for TestRound {
        fn start(&self) -> Result<(), Error> {
            Ok(())
        }
        fn update(&self) -> Result<(), Error> {
            Ok(())
        }
        fn can_proceed(&self) -> bool {
            true
        }
        fn next_round(&self) -> Box<dyn Round> {
            Box::new(TestRound)
        }
        fn waiting_for(&self) -> Vec<PartyID> {
            vec![]
        }
        fn wrap_error(&self, err: Box<dyn std::error::Error>, culprits: Vec<PartyID>) -> Error {
            Error::new(err, "test".to_string(), 0, None, culprits)
        }
        fn params(&self) -> &Parameters {
            unimplemented!()
        }
        fn round_number(&self) -> u32 {
            1
        }
    }

    #[test]
    fn test_base_party_creation() {
        let first_round = Box::new(TestRound);
        let base_party = BaseParty::new(first_round);

        assert!(!base_party.running());
    }
}
use crate::tss::error::Error;
use crate::tss::message::ParsedMessage;
use crate::tss::party_id::PartyID;
use crate::tss::params::Parameters;
