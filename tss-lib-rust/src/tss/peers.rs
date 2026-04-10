pub struct PeerContext {
    party_ids: Vec<PartyID>,
}

impl PeerContext {
    pub fn new(party_ids: Vec<PartyID>) -> Self {
        PeerContext { party_ids }
    }
}
use crate::tss::party_id::PartyID;
