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
use crate::eddsa::keygen::messages::{KGRound1Message, KGRound2Message1, KGRound2Message2, KGRound3Message}; // Removed unused imports: HashCommitment, VssShare, HashDeCommitment
use crate::eddsa::keygen::save_data::{LocalPartySaveData, LocalPreParams}; // Removed unused imports: PaillierPrivateKey, EdDSASecretShareScalar
// --- TSS Core Imports ---
use crate::tss::{
    params::Parameters,
    party_id::{PartyID, SortedPartyIDs}, // Added SortedPartyIDs
    error::TssError, // Renamed Error -> TssError for clarity
    message::{Message as TssMessage, ParsedMessage}, // Renamed Message -> TssMessage, ParsedMessage struct
    party::{Party as TssParty, Round as TssRound, BaseParty}, // Renamed Party -> TssParty, Round -> TssRound
};
// --- End TSS Core Imports ---

use num_traits::{One, Zero};
use std::error::Error as StdError; // Use standard Error trait
use std::time::Duration;
use crate::eddsa::keygen::rounds::Round1;
use crate::crypto::paillier;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use prost::Message as ProstMessage; // Renamed to avoid conflict with local trait

// Removed placeholder imports/structs
// use crate::common;
// use crate::crypto::commitments as cmt;
// use crate::crypto::vss;

#[derive(Clone, Debug)] // Added Clone and Debug
pub struct KeygenPartyTmpData {
    // pub temp_ecdsa_keygen_data: crate::protocols::ecdsa::keygen::KeygenTempData, // Assuming this is handled elsewhere
    // pub dln_proof_1: Option<crate::protocols::dln_proof::Proof>, // Assuming this is handled elsewhere
    // pub dln_proof_2: Option<crate::protocols::dln_proof::Proof>, // Assuming this is handled elsewhere
    pub round_1_messages: HashMap<PartyID, KGRound1Message>, // Use actual message types
    pub round_2_messages1: HashMap<PartyID, KGRound2Message1>, // Use actual message types
    pub round_2_messages2: HashMap<PartyID, KGRound2Message2>, // Use actual message types
    pub round_3_messages: HashMap<PartyID, KGRound3Message>, // Use actual message types
    // Added fields from previous placeholder LocalTempData
    pub ui: Option<BigInt>,
    pub kgcs: Vec<Option<crate::crypto::commitments::HashCommitment>>, // Use actual type
    pub vs: Option<Vec<crate::crypto::vss::VssShare>>, // Use actual type
    pub shares: Option<Vec<crate::crypto::vss::VssShare>>, // Use actual type
    pub de_commit_poly_g: Option<crate::crypto::commitments::HashDeCommitment>, // Use actual type
    pub ssid: Option<Vec<u8>>,
    pub ssid_nonce: Option<BigInt>,
}

impl KeygenPartyTmpData {
    pub fn new() -> Self {
        Self {
            round_1_messages: HashMap::new(),
            round_2_messages1: HashMap::new(),
            round_2_messages2: HashMap::new(),
            round_3_messages: HashMap::new(),
            ui: None,
            kgcs: Vec::new(),
            vs: None,
            shares: None,
            de_commit_poly_g: None,
            ssid: None,
            ssid_nonce: None,
        }
    }
}

// Renamed to avoid conflict with KeygenPartyTmpData above
#[derive(Clone, Debug)] // Added Clone and Debug
pub struct KeyGenPartySaveData {
    pub local_party_id: PartyID,
    pub parties: SortedPartyIDs,
    pub threshold: usize,
    // pub ecdsa_data: crate::protocols::ecdsa::keygen::KeygenLocalPartySaveData, // Assuming this is handled elsewhere
    pub started: bool,
    // Added fields from previous placeholder LocalPartySaveData
    pub paillier_pk: Option<paillier::PublicKey>,
    pub paillier_sk: Option<paillier::PrivateKey>,
    pub eddsa_pk_sum: Option<BigInt>, // Or appropriate Point type
    pub eddsa_sk_sum_share: Option<BigInt>, // Or appropriate Scalar type
    pub x_i: Option<BigInt>, // Or appropriate Scalar type
    pub share_id: Option<BigInt>, // Or appropriate Scalar type
    pub all_pks: Vec<Option<BigInt>>, // Or Point type
    pub all_shares_sum: Vec<Option<BigInt>>, // Or Point type
}

impl KeyGenPartySaveData {
    pub fn new(
        local_party_id: PartyID,
        parties: SortedPartyIDs,
        threshold: usize,
        started: bool,
    ) -> Self {
        Self {
            local_party_id,
            parties,
            threshold,
            started,
            paillier_pk: None,
            paillier_sk: None,
            eddsa_pk_sum: None,
            eddsa_sk_sum_share: None,
            x_i: None,
            share_id: None,
            all_pks: vec![None; parties.len()],
            all_shares_sum: vec![None; parties.len()],
        }
    }
}


pub struct LocalParty {
    pub params: Arc<Parameters>, // Use Arc for shared ownership
    pub temp: Arc<Mutex<KeygenPartyTmpData>>,
    pub data: Arc<Mutex<KeyGenPartySaveData>>,
    pub out: Option<Sender<TssMessage>>, // Use actual TssMessage
    pub end: Option<Sender<KeyGenPartySaveData>>, // Use actual SaveData
    base: BaseParty, // Embed the core BaseParty for round management
    // Removed messages map, assume BaseParty/Round handles message storage/retrieval needs
}

// Removed placeholder LocalMessageStore

// Removed placeholder SaveData::new

// Removed placeholder KeygenMessage enum (handled by ParsedMessage)

// Removed placeholder types: Round, Error, HashCommitment, Vs, Shares, HashDeCommitment

// Placeholder for Germain Safe Prime type
#[derive(Debug, Clone)]
pub struct GermainSafePrime {
    p: BigInt, // The safe prime (2q + 1)
    q: BigInt, // The Sophie Germain prime (q)
}

impl GermainSafePrime {
    // Placeholder constructor
    pub fn new(p: BigInt, q: BigInt) -> Self {
        GermainSafePrime { p, q }
    }
    pub fn safe_prime(&self) -> &BigInt {
        &self.p
    }
    pub fn prime(&self) -> &BigInt {
        &self.q
    }
}

// Placeholder for Safe Prime Generation
mod common {
    use super::{BigInt, Error, GermainSafePrime, RandBigInt};
    use num_bigint::RandBigInt;
    use num_traits::One;
    use rand::rngs::OsRng; // Or another CSPRNG
    use std::error::Error;

    pub fn get_random_safe_primes(
        rng: &mut dyn rand::RngCore,
        bits: usize,
        count: usize,
    ) -> Result<Vec<GermainSafePrime>, Box<dyn Error>> {
        println!("Warning: Using placeholder safe prime generation.");
        let mut primes = Vec::with_capacity(count);
        for _ in 0..count {
            // Replace with actual safe prime generation logic
            let q = rng.gen_bigint(bits / 2); // Dummy Sophie Germain prime
            let p = BigInt::from(2) * &q + BigInt::one(); // Dummy safe prime
            primes.push(GermainSafePrime::new(p, q));
        }
        Ok(primes)
    }

    // Placeholder for modular exponentiation/inverse needed below
    pub fn mod_inverse(a: &BigInt, modulus: &BigInt) -> Option<BigInt> {
       // Replace with actual modular inverse implementation
       // This is a basic extended Euclidean algorithm, potentially slow/incorrect for crypto
       let egcd = extended_gcd(a, modulus);
       if egcd.gcd != BigInt::one() {
            None // Inverse doesn't exist
       } else {
            let mut res = egcd.x;
            while res < BigInt::zero() {
                res += modulus;
            }
            Some(res % modulus)
       }
    }

    // Helper for placeholder mod_inverse
    struct ExtendedGcdResult {
        gcd: BigInt,
        x: BigInt,
        _y: BigInt,
    }

    fn extended_gcd(a: &BigInt, b: &BigInt) -> ExtendedGcdResult {
        if *a == BigInt::zero() {
            return ExtendedGcdResult { gcd: b.clone(), x: BigInt::zero(), _y: BigInt::one() };
        }
        let egcd = extended_gcd(&(b % a), a);
        ExtendedGcdResult {
            gcd: egcd.gcd,
            x: egcd._y - (b / a) * &egcd.x,
            _y: egcd.x,
        }
    }

    // Placeholder for generating random relatively prime integer
    pub fn get_random_positive_relatively_prime_int(
        rng: &mut dyn rand::RngCore,
        modulus: &BigInt
    ) -> BigInt {
        // Replace with actual implementation ensuring gcd(result, modulus) == 1
        println!("Warning: Using placeholder for get_random_positive_relatively_prime_int");
        loop {
             let r = rng.gen_bigint_range(&BigInt::one(), modulus);
             if extended_gcd(&r, modulus).gcd == BigInt::one() {
                return r;
             }
        }
    }

     pub fn mod_exp(base: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
         // Replace with efficient modular exponentiation (e.g., using num-bigint's modpow)
         base.modpow(exponent, modulus)
     }

    pub fn mod_mul(a: &BigInt, b: &BigInt, modulus: &BigInt) -> BigInt {
        (a * b) % modulus
    }
}

const PAILLIER_MODULUS_LEN: usize = 2048;
const SAFE_PRIME_BIT_LEN: usize = 1024;

// Function to generate pre-parameters, similar to Go's GeneratePreParams
// Currently synchronous, ignores timeout and concurrency arguments.
pub fn generate_pre_params(
    _timeout: Duration,                // TODO: Implement timeout
    _optional_concurrency: Option<usize>, // TODO: Implement concurrency
) -> Result<LocalPreParams, Box<dyn StdError>> { // Use standard Error trait
    println!(
        "generating local pre-params for party ID {}...",
        "None" // TODO: Add party ID context if needed
    );

    let mut rng = rand::rngs::OsRng; // Use a cryptographically secure RNG

    // 1. Generate Paillier public/private key pair
    let (paillier_pk, paillier_sk) = match paillier::generate_keypair(&mut rng, PAILLIER_MODULUS_LEN) {
        Ok(pair) => pair,
        Err(e) => return Err(Box::new(e)), // Propagate Paillier error
    };

    // 2. Generate Safe Primes p, q for Pedersen commitments
    let safe_primes = match common::get_random_safe_primes(&mut rng, SAFE_PRIME_BIT_LEN, 2) {
        Ok(primes) => primes,
        Err(e) => return Err(e), // Propagate safe prime generation error
    };
    let p = safe_primes[0].clone();
    let q = safe_primes[1].clone();

    // 3. Generate NTilde = p*q, h1, h2
    let n_tilde = p.safe_prime() * q.safe_prime();
    let h1 = common::get_random_positive_relatively_prime_int(&mut rng, &n_tilde);
    let h2 = common::get_random_positive_relatively_prime_int(&mut rng, &n_tilde);

    println!("pre-params generated!"); // Removed party ID for now
    Ok(LocalPreParams {
        paillier_sk, // Keep private key for the party
        paillier_pk, // Public key might be shared later
        n_tilde,
        h1,
        h2,
        p, // Keep safe primes if needed for proofs
        q,
    })
}

impl LocalParty {
    pub fn new(
        params: Parameters, // Take Parameters by value
        out: Option<Sender<TssMessage>>, // Use actual TssMessage
        end: Option<Sender<KeyGenPartySaveData>>, // Use actual SaveData
        optional_pre_params: Option<LocalPreParams>,
    ) -> Result<Self, TssError> { // Return TssError
        let party_id = params.party_id().clone();
        let party_count = params.party_count();
        let threshold = params.threshold();
        let parties = params.parties().clone();

        let pre_params = match optional_pre_params {
            Some(p) => p,
            None => generate_pre_params(Duration::from_secs(300), None) // Use defaults
                .map_err(|e| TssError::new(e, "pre-params generation".to_string(), 0, Some(party_id.clone()), vec![]))?,
        };

        // TODO: Validate pre_params against Parameters if necessary

        let data = KeyGenPartySaveData {
            local_party_id: party_id.clone(),
            parties: parties.clone(),
            threshold,
            started: false,
            paillier_pk: Some(pre_params.paillier_pk), // Store public Paillier key
            paillier_sk: Some(pre_params.paillier_sk), // Store private Paillier key
            // Initialize other fields as needed
            eddsa_pk_sum: None,
            eddsa_sk_sum_share: None,
            x_i: None,
            share_id: None,
            all_pks: vec![None; party_count],
            all_shares_sum: vec![None; party_count],
        };

        let temp = KeygenPartyTmpData::new();

        let shared_params = Arc::new(params);
        let shared_temp = Arc::new(Mutex::new(temp));
        let shared_data = Arc::new(Mutex::new(data));

        let first_round = Box::new(Round1::new(
            shared_params.clone(),
            shared_data.clone(),
            shared_temp.clone(),
        ));

        let base = BaseParty::new(first_round);

        Ok(Self {
            params: shared_params,
            temp: shared_temp,
            data: shared_data,
            out,
            end,
            base, // Initialize BaseParty
        })
    }

    // Helper to get a mutable reference to the current round
    fn current_round_mut(&mut self) -> Result<&mut Box<dyn TssRound>, TssError> {
         self.base.current_round_mut().ok_or_else(|| TssError::new(
             Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Party not running")), // TODO: Better error type
             "access round".to_string(), 0, Some(self.party_id()), vec![]
         ))
    }

    // Helper to get an immutable reference to the current round
    fn current_round(&self) -> Result<&Box<dyn TssRound>, TssError> {
         self.base.current_round().ok_or_else(|| TssError::new(
             Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Party not running")), // TODO: Better error type
             "access round".to_string(), 0, Some(self.party_id()), vec![]
         ))
    }

     // Helper function to parse wire bytes into a specific round message type
    // This is a conceptual placeholder. Actual parsing depends on message structure.
    fn parse_wire_message(
        &self,
        wire_bytes: &[u8],
        from: &PartyID,
        is_broadcast: bool
    ) -> Result<ParsedMessage, TssError> {
        // TODO: Implement actual parsing logic based on wire format
        // This might involve looking at round number or message type hints
        // For now, return a placeholder ParsedMessage
        println!("Warning: Using placeholder parse_wire_message");

        // Determine round number (e.g., from wire_bytes or assume current round)
        let round_num = self.current_round().map(|r| r.round_number()).unwrap_or(0); // Example

        Ok(ParsedMessage {
            wire_bytes: wire_bytes.to_vec(),
            from: from.clone(),
            to: if is_broadcast { None } else { Some(vec![self.party_id()]) }, // Assume P2P if not broadcast
            is_broadcast,
            round: round_num,
            // message_type: Determine based on parsing // TODO
            // content: Actual parsed content // TODO
        })
    }
}

impl TssParty for LocalParty {
    fn start(&self) -> Result<(), TssError> {
        // Use BaseParty to start the process
        self.base.start()
    }

    fn update(&self, msg: ParsedMessage) -> Result<bool, TssError> {
         // Use BaseParty to update the current round
         self.base.update(msg)
    }

    fn update_from_bytes(&self, wire_bytes: &[u8], from: &PartyID, is_broadcast: bool) -> Result<bool, TssError> {
        let parsed_msg = self.parse_wire_message(wire_bytes, from, is_broadcast)?;
        self.update(parsed_msg)
    }

    fn running(&self) -> bool {
        // Use BaseParty to check if running
        self.base.running()
    }

     fn waiting_for(&self) -> Vec<PartyID> {
         // Delegate to BaseParty/current round
         self.base.waiting_for()
     }

    fn validate_message(&self, msg: ParsedMessage) -> Result<bool, TssError> {
        // Delegate validation logic to the current round via BaseParty
        self.base.validate_message(msg)
    }

    fn store_message(&self, msg: ParsedMessage) -> Result<bool, TssError> {
        // Delegate storing logic to the current round via BaseParty
        self.base.store_message(msg)
    }

    fn first_round(&self) -> Box<dyn TssRound> {
        // Delegate to BaseParty
        self.base.first_round()
    }

    fn wrap_error(&self, err: Box<dyn StdError>, culprits: Vec<PartyID>) -> TssError {
        // Delegate error wrapping, potentially adding party context
         let round_num = self.current_round().map(|r| r.round_number()).unwrap_or(0);
         TssError::new(err, "keygen".to_string(), round_num, Some(self.party_id()), culprits)
    }

    fn party_id(&self) -> PartyID {
        self.params.party_id().clone()
    }
}

impl fmt::Display for LocalParty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Safely access data for display
        match self.data.lock() {
            Ok(data_guard) => write!(
                f,
                "LocalParty[id: {}, threshold: {}, parties: {}]",
                data_guard.local_party_id.id, // Assuming PartyID has an 'id' field
                data_guard.threshold,
                data_guard.parties.len()
            ),
            Err(_) => write!(f, "LocalParty[id: <locked>, threshold: <locked>, parties: <locked>]"), // Handle lock poisoning
        }
    }
}


// --- Test Section ---
// TODO: Update tests to use the new structure and actual TSS types

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tss::party_id::PartyID;
    use crate::tss::params::Parameters;
    use std::sync::mpsc;

    // Helper to create basic parameters for testing
    fn create_test_params(id: &str, index: usize, party_count: usize, threshold: usize) -> Parameters {
        let party_id = PartyID { id: id.to_string(), moniker: id.to_string(), key: vec![index as u8] };
        let parties = (0..party_count)
            .map(|i| PartyID { id: format!("p{}", i), moniker: format!("p{}", i), key: vec![i as u8] })
            .collect::<Vec<_>>();
        Parameters::new(party_id, parties, threshold).unwrap()
    }


    #[test]
    fn test_generate_pre_params_success() {
        // Use a short timeout for testing, but it's currently ignored
        let result = generate_pre_params(Duration::from_secs(1), None);
        assert!(result.is_ok());
        let pre_params = result.unwrap();

        // Basic checks on the generated parameters
        assert!(pre_params.paillier_sk.validate().is_ok());
        assert_eq!(pre_params.paillier_sk.public_key(), &pre_params.paillier_pk);
        assert!(pre_params.n_tilde > BigInt::zero());
        assert!(pre_params.h1 > BigInt::zero() && pre_params.h1 < pre_params.n_tilde);
        assert!(pre_params.h2 > BigInt::zero() && pre_params.h2 < pre_params.n_tilde);
        // TODO: Add checks for safe prime properties if needed (e.g., bit length)
    }

    // #[test] // Timeout test needs actual implementation
    // fn test_generate_pre_params_timeout_placeholder() {
    //     // This test currently does nothing as timeout is ignored.
    //     // To make this meaningful, the generation function needs
    //     // to implement timeout logic (e.g., using threads or async).
    //     let short_timeout = Duration::from_millis(1);
    //     let result = generate_pre_params(short_timeout, None);
    //     // If timeout were implemented, we might expect an error here.
    //     // For now, it will likely succeed or fail based on generation logic.
    //     println!("Placeholder timeout test result (timeout not implemented): {:?}", result.is_ok());
    //     // assert!(result.is_err()); // Example assertion if timeout caused an error
    // }

     #[test]
     fn test_local_party_new_success() {
         let params = create_test_params("p0", 0, 3, 1);
         let (out_tx, _) = mpsc::channel::<TssMessage>();
         let (end_tx, _) = mpsc::channel::<KeyGenPartySaveData>();

         let party_result = LocalParty::new(params, Some(out_tx), Some(end_tx), None);
         assert!(party_result.is_ok());
         let party = party_result.unwrap();

         assert_eq!(party.party_id().id, "p0");
         assert_eq!(party.params.threshold(), 1);
         assert_eq!(party.params.party_count(), 3);
         assert!(!party.running()); // Should not be running initially
         {
             let data = party.data.lock().unwrap();
             assert!(!data.started);
             assert!(data.paillier_pk.is_some());
             assert!(data.paillier_sk.is_some());
         }
         {
             let temp = party.temp.lock().unwrap();
            // assert temp data is initialized correctly if needed
             assert!(temp.round_1_messages.is_empty());
         }
     }

     #[test]
     fn test_local_party_new_with_preparams() {
        let pre_params = generate_pre_params(Duration::from_secs(5), None).unwrap();
        let params = create_test_params("p1", 1, 2, 1);
        let (out_tx, _) = mpsc::channel::<TssMessage>();
        let (end_tx, _) = mpsc::channel::<KeyGenPartySaveData>();

        let party_result = LocalParty::new(params, Some(out_tx), Some(end_tx), Some(pre_params.clone()));
        assert!(party_result.is_ok());
        let party = party_result.unwrap();

        assert_eq!(party.party_id().id, "p1");
        {
             let data = party.data.lock().unwrap();
             assert_eq!(data.paillier_pk.as_ref().unwrap(), &pre_params.paillier_pk);
             assert_eq!(data.paillier_sk.as_ref().unwrap().public_key(), &pre_params.paillier_pk); // Check consistency
             // Private keys won't be directly comparable without serialization/equality impl
         }
     }

     // TODO: Add tests for start, update, wrap_error, etc.
     // These will likely require mocking rounds or providing simple round implementations.

}


// --- Integration Test Section ---
// TODO: Update E2E test to use the new structure and actual TSS types

#[cfg(test)]
mod keygen_integration_tests {
    use super::*;
    use crate::tss::{party_id::PartyID, params::Parameters, message::TssMessage};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::thread;
    use std::time::Duration;
    use num_bigint::BigInt;
    use std::collections::{HashMap, VecDeque};
    use crate::crypto::secp256k1_scalar::Secp256k1Scalar; // Example scalar type

    // Helper to create test Parameters
    fn create_test_params(id: &str, index: usize, party_count: usize, threshold: usize) -> Parameters {
         let party_id = PartyID { id: id.to_string(), moniker: id.to_string(), key: vec![index as u8] };
         let parties_vec = (0..party_count)
            .map(|i| PartyID { id: format!("p{}", i), moniker: format!("p{}", i), key: vec![i as u8] })
            .collect::<Vec<_>>();
         let parties = SortedPartyIDs::from_unsorted_parties(&parties_vec).unwrap();
        Parameters::new(party_id, parties, threshold).unwrap() // Now takes SortedPartyIDs
    }

    // Helper to generate PartyIDs
    // fn generate_test_party_ids(count: usize) -> Vec<PartyID> { // Now using create_test_params
    //     (0..count)
    //         .map(|i| PartyID { id: format!("p{}", i), moniker: format!("p{}", i), key: vec![i as u8] })
    //         .collect()
    // }

    // Placeholder for parsing (replace with actual logic or mock)
    // fn test_parse_message(bytes: &[u8], from: &PartyID, is_broadcast: bool) -> ParsedMessage {
    //     // In a real test, this should parse based on round/message type
    //     println!("Integration Test: Parsing {} bytes from {} (broadcast: {})", bytes.len(), from.id, is_broadcast);
    //     ParsedMessage {
    //          wire_bytes: bytes.to_vec(),
    //          from: from.clone(),
    //          to: None, // Assume broadcast or handled by routing logic
    //          is_broadcast,
    //          round: 0, // Placeholder - needs actual round info
    //          // message_type: todo!(),
    //          // content: todo!(),
    //      }
    // }

     // Represents a message flowing through the test network
     // pub struct TestMessage { // Now using TssMessage directly
     //     pub wire_bytes: Vec<u8>,
     //     pub from_party_index: usize,
     //     pub is_broadcast: bool,
     // }

    #[test]
    #[ignore] // Ignore until rounds are implemented and test is updated
    fn test_e2e_keygen_concurrent() {
        let party_count = 3;
        let threshold = 1; // t = 1 for a 2/3 setup

        // 1. Create channels for communication and results
        let mut out_rxs = Vec::new();
        let mut out_txs = Vec::new();
        let mut end_rxs = Vec::new();
        let mut end_txs = Vec::new();

        for _ in 0..party_count {
            let (out_tx, out_rx) = mpsc::channel::<TssMessage>(); // Use actual TssMessage
            let (end_tx, end_rx) = mpsc::channel::<KeyGenPartySaveData>(); // Use actual SaveData
            out_txs.push(Some(out_tx)); // Wrap in Option for take() later
            out_rxs.push(out_rx);
            end_txs.push(Some(end_tx)); // Wrap in Option for take() later
            end_rxs.push(end_rx);
        }

        // 2. Create and start parties in separate threads
        let mut party_handles = Vec::new();
        let mut parties_vec = Vec::new(); // Keep track of Party structs if needed for direct calls

        for i in 0..party_count {
            let params = create_test_params(&format!("p{}", i), i, party_count, threshold);
            // Take the Option<Sender> for this party
            let out_tx = out_txs[i].take().unwrap();
            let end_tx = end_txs[i].take().unwrap();

            // Use a shared Arc<Parameters> if rounds need it
            let shared_params = Arc::new(params);

            // Create the party
            // Need pre-params generation or loading here
            let pre_params = generate_pre_params(Duration::from_secs(5), None).expect("Pre-param gen failed");
            let party = LocalParty::new(
                (*shared_params).clone(), // Clone Parameters struct if needed by new
                Some(out_tx),
                Some(end_tx),
                Some(pre_params)
            ).expect("Failed to create party");

            // Wrap party in Arc for thread safety if needed, though BaseParty handles internal state
            let party_arc = Arc::new(party);
            parties_vec.push(party_arc.clone()); // Store Arc<LocalParty>

            let handle = thread::spawn(move || {
                println!("Party {} starting...", party_arc.party_id().id);
                if let Err(e) = party_arc.start() {
                    eprintln!("Party {} failed to start: {:?}", party_arc.party_id().id, e);
                }
                println!("Party {} start called.", party_arc.party_id().id);
                // Keep thread alive while party is running? Or rely on message loop?
                // For now, the thread just starts the party and exits.
                // The message loop below will drive progress.
            });
            party_handles.push(handle);
        }

        // 3. Simulate the network: Route messages between parties
        let mut message_queue: VecDeque<TssMessage> = VecDeque::new();
        let mut completed_parties = 0;
        let start_time = std::time::Instant::now();
        let timeout = Duration::from_secs(60); // Timeout for the entire process

        'network_loop: loop {
            if completed_parties == party_count {
                println!("All parties finished.");
                break;
            }
            if start_time.elapsed() > timeout {
                panic!("E2E test timed out!");
            }

            // Check for outgoing messages from any party
            for i in 0..party_count {
                 match out_rxs[i].try_recv() {
                     Ok(msg) => {
                         println!(
                             "Network: Received msg from P{} ({} bytes, bc: {}, round: {})",
                             i, msg.wire_bytes.len(), msg.is_broadcast, msg.round // Access fields directly
                         );
                         message_queue.push_back(msg);
                     },
                     Err(mpsc::TryRecvError::Empty) => {}, // No message yet
                     Err(mpsc::TryRecvError::Disconnected) => {
                         // This shouldn't happen unless a party panics or drops sender early
                         eprintln!("Warning: Out channel disconnected for party P{}", i);
                     }
                 }
             }


            // Process one message from the queue
            if let Some(msg) = message_queue.pop_front() {
                let from_party_id = msg.from.clone(); // Get sender ID from message

                if msg.is_broadcast {
                    println!("Network: Broadcasting msg from {} (round {})", from_party_id.id, msg.round);
                    for j in 0..party_count {
                        // Don't send back to sender (usually handled by round logic)
                        if parties_vec[j].party_id() != from_party_id {
                            // Need to call update on the correct party instance
                            // The Arc<LocalParty> is needed here
                            let party_to_update = parties_vec[j].clone();
                            let msg_clone = msg.clone(); // Clone message for each recipient
                             // Spawn a task or handle potential blocking? For now, direct call.
                             thread::spawn(move || { // Simulate async delivery/processing
                                 if let Err(e) = party_to_update.update(msg_clone) {
                                    eprintln!("Party {} update error: {:?}", party_to_update.party_id().id, e);
                                 }
                             });
                        }
                    }
                } else {
                    // P2P message - find the recipient(s)
                    if let Some(recipients) = &msg.to {
                         println!("Network: Routing P2P msg from {} to {:?} (round {})", from_party_id.id, recipients.iter().map(|p| p.id.clone()).collect::<Vec<_>>(), msg.round);
                         for recipient_id in recipients {
                            // Find the party instance corresponding to recipient_id
                            if let Some(recipient_party) = parties_vec.iter().find(|p| p.party_id() == *recipient_id) {
                                let party_to_update = recipient_party.clone();
                                let msg_clone = msg.clone();
                                thread::spawn(move || { // Simulate async delivery/processing
                                     if let Err(e) = party_to_update.update(msg_clone) {
                                        eprintln!("Party {} update error: {:?}", party_to_update.party_id().id, e);
                                     }
                                 });
                            } else {
                                eprintln!("Network: Error - P2P recipient {} not found!", recipient_id.id);
                            }
                        }
                    } else {
                         eprintln!("Network: Error - P2P message from {} has no recipient list!", from_party_id.id);
                    }
                }
            } else {
                 // No messages in queue, check if any party finished
                 for i in 0..party_count {
                     match end_rxs[i].try_recv() {
                         Ok(save_data) => {
                             println!("Network: Party P{} finished!", i);
                             completed_parties += 1;
                             // Mark this party's receiver as done? Or just count?
                             // We need to store the save_data result for verification later.
                             // Let's assume we collect them in a results map.
                         },
                         Err(mpsc::TryRecvError::Empty) => {}, // Not finished yet
                         Err(mpsc::TryRecvError::Disconnected) => {
                             eprintln!("Warning: End channel disconnected for party P{}", i);
                             // Potentially increment completed_parties if disconnected means finished/crashed
                             // Or handle as an error depending on test requirements
                         }
                     }
                 }
                 // Avoid busy-waiting if no messages and no completions
                 if message_queue.is_empty() && completed_parties < party_count {
                     thread::sleep(Duration::from_millis(10));
                 }
            }
        }


        // 4. Wait for all party threads to finish (optional, start is async)
        // for handle in party_handles {
        //     handle.join().expect("Party thread panicked");
        // }

        // 5. Collect results from end channels
        let mut results = Vec::with_capacity(party_count);
        for i in 0..party_count {
            // Use recv_timeout on the actual receivers stored earlier
            match end_rxs[i].recv_timeout(Duration::from_secs(10)) {
                 Ok(save_data) => results.push(save_data),
                 Err(e) => panic!("Party P{} failed to send result: {:?}", i, e),
             }
        }

        // 6. Validate results
        assert_eq!(results.len(), party_count);
        println!("Collected {} results. Validating...", results.len());

        let first_pk = results[0].eddsa_pk_sum.as_ref().expect("Party 0 missing PK sum");
        let first_xi = results[0].x_i.as_ref().expect("Party 0 missing x_i"); // Assuming x_i is the secret share

        for i in 1..party_count {
            let pk = results[i].eddsa_pk_sum.as_ref().expect(&format!("Party {} missing PK sum", i));
            let xi = results[i].x_i.as_ref().expect(&format!("Party {} missing x_i", i));

            assert_eq!(pk, first_pk, "Public keys differ between party 0 and {}", i);
            // Secret shares (x_i) SHOULD be different
            assert_ne!(xi, first_xi, "Secret shares x_i are unexpectedly the same for party 0 and {}", i);

            // TODO: More sophisticated validation:
            // - Check Paillier keys if needed
            // - Potentially reconstruct the combined secret key from shares (if using Shamir over a known field)
            // - Verify the relationship between secret shares and the public key point using ECC math
            //   (e.g., sum(x_i * G) == combined_pk) - requires ECC library integration.
        }

        println!("E2E Keygen Test Successful!");
    }
}

// Removed placeholder KeygenPartyTmpData and KeyGenPartySaveData structs (defined earlier)
// Removed placeholder new methods for them
