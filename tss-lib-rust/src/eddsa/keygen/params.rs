// Parameters specific to the EDDSA keygen protocol

use std::sync::Arc;
use crate::tss::{
    curve::CurveName,
    party_id::{PartyID, SortedPartyIDs},
};
use crate::tss::peers::PeerContext; // Keep PeerContext if needed for communication

#[derive(Clone, Debug)] // Added Debug
pub struct Parameters {
    curve: CurveName,
    peer_ctx: Arc<PeerContext>, // Context for peer communication?
    party_id: PartyID,          // This party's ID
    parties: Arc<SortedPartyIDs>, // All parties, sorted
    party_count: usize,
    threshold: usize,
}

impl Parameters {
    pub fn new(
        curve: CurveName,
        peer_ctx: Arc<PeerContext>,
        party_id: PartyID,
        parties: Arc<SortedPartyIDs>,
        threshold: usize,
    ) -> Self {
        let party_count = parties.len();
        Parameters {
            curve,
            peer_ctx,
            party_id,
            parties,
            party_count,
            threshold,
        }
    }

    // Public accessors matching the usage seen in keygen code
    pub fn curve(&self) -> CurveName {
        self.curve
    }

    pub fn peer_ctx(&self) -> &Arc<PeerContext> {
        &self.peer_ctx
    }

    pub fn party_id(&self) -> &PartyID {
        &self.party_id
    }

    pub fn parties(&self) -> &Arc<SortedPartyIDs> {
        &self.parties
    }

    pub fn party_count(&self) -> usize {
        self.party_count
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    // Helper to get party index - useful for rounds
    pub fn party_index(&self) -> Option<usize> {
        self.parties.find_by_id(&self.party_id)
    }
} 