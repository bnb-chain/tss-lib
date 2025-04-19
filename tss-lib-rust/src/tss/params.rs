use k256::elliptic_curve::sec1::ToEncodedPoint;
use std::time::Duration;

pub struct Parameters {
    ec: Box<dyn ToEncodedPoint>,
    party_id: PartyID,
    parties: PeerContext,
    party_count: usize,
    threshold: usize,
    concurrency: usize,
    safe_prime_gen_timeout: Duration,
    nonce: usize,
    no_proof_mod: bool,
    no_proof_fac: bool,
}

impl Parameters {
    pub fn new(ec: Box<dyn ToEncodedPoint>, party_id: PartyID, parties: PeerContext, party_count: usize, threshold: usize) -> Self {
        Parameters {
            ec,
            party_id,
            parties,
            party_count,
            threshold,
            concurrency: num_cpus::get(),
            safe_prime_gen_timeout: Duration::from_secs(300),
            nonce: 0,
            no_proof_mod: false,
            no_proof_fac: false,
        }
    }
}
