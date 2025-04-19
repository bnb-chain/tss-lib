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
#[cfg(test)]
mod tests {
    use super::*;
    use k256::Secp256k1;

    #[test]
    fn test_parameters_creation() {
        let ec = Box::new(Secp256k1::default());
        let party_id = PartyID::new("id".to_string(), "moniker".to_string(), BigInt::from(1));
        let parties = PeerContext::new(vec![party_id.clone()]);
        let params = Parameters::new(ec, party_id.clone(), parties, 1, 1);

        assert_eq!(params.party_count, 1);
        assert_eq!(params.threshold, 1);
    }
}
use crate::tss::party_id::PartyID;
use crate::tss::peers::PeerContext;
