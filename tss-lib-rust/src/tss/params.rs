// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/tss/params.go

use crate::tss::{
    curve::Curve,
    party_id::PartyID,
};
use std::{{
    sync::Arc,
    time::Duration,
}};
use crate::common::peer_context::PeerContext;

// Using a fixed value, similar to Go's default
const DEFAULT_CONCURRENCY: usize = 1; // Go uses runtime.GOMAXPROCS(0)
const DEFAULT_SAFE_PRIME_GEN_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Parameters defines the common parameters for all TSS protocols.
#[derive(Clone, Debug)] // Debug requires PeerContext to be Debug
pub struct Parameters {
    ec: Curve,
    // Use Arc for shared ownership of context and party ID
    party_id: Arc<PartyID>,
    parties: Arc<PeerContext>,
    party_count: usize,
    threshold: usize,
    concurrency: usize,
    safe_prime_gen_timeout: Duration,
    // TODO: Add nonce if needed for proof session info
    // nonce: u64,
    // Keygen-specific options
    no_proof_mod: bool,
    no_proof_fac: bool,
    // TODO: Random sources - requires defining a suitable trait or using `rand` crate types
    // partial_key_rand: Arc<dyn RngCore + CryptoRng + Send + Sync>,
    // rand: Arc<dyn RngCore + CryptoRng + Send + Sync>,
}

impl Parameters {
    /// Creates new TSS parameters.
    pub fn new(
        ec: Curve,
        parties: Arc<PeerContext>,
        party_id: Arc<PartyID>,
        party_count: usize,
        threshold: usize,
    ) -> Self {
        // Basic validation
        assert!(threshold < party_count, "Threshold must be less than party count");
        assert!(parties.len() == party_count, "Party count mismatch");
        assert!(parties.party_ids().iter().any(|p| **p == *party_id), "Current party ID not found in party context");

        Self {
            ec,
            party_id,
            parties,
            party_count,
            threshold,
            concurrency: DEFAULT_CONCURRENCY,
            safe_prime_gen_timeout: DEFAULT_SAFE_PRIME_GEN_TIMEOUT,
            no_proof_mod: false,
            no_proof_fac: false,
            // Initialize RNGs later or require them in constructor
        }
    }

    // --- Accessors ---
    pub fn ec(&self) -> Curve { self.ec }
    pub fn parties(&self) -> &Arc<PeerContext> { &self.parties }
    pub fn party_id(&self) -> &Arc<PartyID> { &self.party_id }
    pub fn party_count(&self) -> usize { self.party_count }
    pub fn threshold(&self) -> usize { self.threshold }
    pub fn concurrency(&self) -> usize { self.concurrency }
    pub fn safe_prime_gen_timeout(&self) -> Duration { self.safe_prime_gen_timeout }
    pub fn no_proof_mod(&self) -> bool { self.no_proof_mod }
    pub fn no_proof_fac(&self) -> bool { self.no_proof_fac }
    // pub fn partial_key_rand(&self) -> &Arc<dyn RngCore + CryptoRng + Send + Sync> { &self.partial_key_rand }
    // pub fn rand(&self) -> &Arc<dyn RngCore + CryptoRng + Send + Sync> { &self.rand }

    // --- Modifiers ---
    /// Sets the concurrency level (must be >= 1).
    pub fn set_concurrency(&mut self, concurrency: usize) -> &mut Self {
        assert!(concurrency >= 1, "Concurrency must be at least 1");
        self.concurrency = concurrency;
        self
    }

    pub fn set_safe_prime_gen_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.safe_prime_gen_timeout = timeout;
        self
    }

    pub fn set_no_proof_mod(&mut self, value: bool) -> &mut Self {
        self.no_proof_mod = value;
        self
    }

    pub fn set_no_proof_fac(&mut self, value: bool) -> &mut Self {
        self.no_proof_fac = value;
        self
    }

    // pub fn set_partial_key_rand(&mut self, rand: Arc<dyn RngCore + CryptoRng + Send + Sync>) -> &mut Self {
    //     self.partial_key_rand = rand;
    //     self
    // }

    // pub fn set_rand(&mut self, rand: Arc<dyn RngCore + CryptoRng + Send + Sync>) -> &mut Self {
    //     self.rand = rand;
    //     self
    // }
}

/// ReSharingParameters defines the parameters for the re-sharing protocol.
#[derive(Clone, Debug)]
pub struct ReSharingParameters {
    // Embeds the original Parameters
    params: Parameters,
    // New committee details
    new_parties: Arc<PeerContext>,
    new_party_count: usize,
    new_threshold: usize,
}

impl ReSharingParameters {
    /// Creates new re-sharing parameters.
    pub fn new(
        ec: Curve,
        old_parties: Arc<PeerContext>,
        new_parties: Arc<PeerContext>,
        party_id: Arc<PartyID>,
        old_party_count: usize,
        old_threshold: usize,
        new_party_count: usize,
        new_threshold: usize,
    ) -> Self {
         // Basic validation
        assert!(old_threshold < old_party_count, "Old threshold must be less than old party count");
        assert!(new_threshold < new_party_count, "New threshold must be less than new party count");
        assert!(old_parties.len() == old_party_count, "Old party count mismatch");
        assert!(new_parties.len() == new_party_count, "New party count mismatch");
        assert!(
            old_parties.party_ids().iter().any(|p| **p == *party_id) ||
            new_parties.party_ids().iter().any(|p| **p == *party_id),
            "Current party ID not found in either old or new party context"
        );

        let params = Parameters::new(ec, old_parties, party_id, old_party_count, old_threshold);
        Self {
            params,
            new_parties,
            new_party_count,
            new_threshold,
        }
    }

    // --- Accessors ---

    // Accessors for the embedded Parameters
    pub fn ec(&self) -> Curve { self.params.ec() }
    pub fn party_id(&self) -> &Arc<PartyID> { self.params.party_id() }
    pub fn concurrency(&self) -> usize { self.params.concurrency() }
    pub fn safe_prime_gen_timeout(&self) -> Duration { self.params.safe_prime_gen_timeout() }
    pub fn no_proof_mod(&self) -> bool { self.params.no_proof_mod() }
    pub fn no_proof_fac(&self) -> bool { self.params.no_proof_fac() }
    // ... add other accessors for Parameters fields if needed

    // Old committee accessors
    pub fn old_parties(&self) -> &Arc<PeerContext> { self.params.parties() }
    pub fn old_party_count(&self) -> usize { self.params.party_count() }
    pub fn old_threshold(&self) -> usize { self.params.threshold() }

    // New committee accessors
    pub fn new_parties(&self) -> &Arc<PeerContext> { &self.new_parties }
    pub fn new_party_count(&self) -> usize { self.new_party_count }
    pub fn new_threshold(&self) -> usize { self.new_threshold }

    /// Returns a combined list of party IDs from both old and new committees.
    pub fn old_and_new_parties(&self) -> Vec<Arc<PartyID>> {
        self.old_parties()
            .party_ids()
            .iter()
            .chain(self.new_parties().party_ids().iter())
            .cloned()
            .collect()
    }

    /// Returns the total count of parties in both old and new committees.
    pub fn old_and_new_party_count(&self) -> usize {
        self.old_party_count() + self.new_party_count()
    }

    /// Checks if the current party belongs to the old committee.
    pub fn is_old_committee(&self) -> bool {
        self.old_parties().party_ids().iter().any(|p| **p == *self.party_id())
    }

    /// Checks if the current party belongs to the new committee.
    pub fn is_new_committee(&self) -> bool {
        self.new_parties().party_ids().iter().any(|p| **p == *self.party_id())
    }

     // --- Modifiers (delegate to embedded params) ---
     // Note: These modify the *internal* params, returning &mut Self for chaining.

    pub fn set_concurrency(&mut self, concurrency: usize) -> &mut Self {
        self.params.set_concurrency(concurrency);
        self
    }

    pub fn set_safe_prime_gen_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.params.set_safe_prime_gen_timeout(timeout);
        self
    }

     pub fn set_no_proof_mod(&mut self, value: bool) -> &mut Self {
        self.params.set_no_proof_mod(value);
        self
    }

    pub fn set_no_proof_fac(&mut self, value: bool) -> &mut Self {
        self.params.set_no_proof_fac(value);
        self
    }
} 