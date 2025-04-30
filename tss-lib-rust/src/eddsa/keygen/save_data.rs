// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// LocalPartySaveData defines the save data structure for the EdDSA keygen protocol.

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
ed25519_dalek::{EdwardsPoint, Scalar as Ed25519Scalar};

// TSS core imports
use crate::tss::party_id::{PartyID, SortedPartyIDs};
use crate::tss::error::Error as TssGenError;

// Keygen specific imports
use crate::eddsa::keygen::TssError;

// Crypto imports
use crate::crypto::vss::Share as VssShare;

// Remove ECDSA-specific LocalPreParams
/*
#[derive(Debug, Clone /* Serialize, Deserialize */)]
pub struct LocalPreParams { ... }
impl LocalPreParams { ... }
*/

// Define LocalSecrets for EdDSA keygen
#[derive(Debug, Clone, Serialize, Deserialize)] // Can derive traits if BigInt supports them
pub struct LocalSecrets {
    // secret fields (not shared, but stored locally)
    pub xi: BigInt, // Use BigInt directly for xi
    pub share_id: BigInt, // Use BigInt directly for kj (party's VSS ID)
}

// Everything in LocalPartySaveData is saved locally when done
#[derive(Debug, Clone, Serialize, Deserialize)] // Use derives if EdwardsPoint supports them (needs feature or wrapper)
pub struct LocalPartySaveData {
    // Embed Secrets directly
    pub local_secrets: LocalSecrets,

    // original indexes (ki in signing preparation phase)
    pub ks: Vec<BigInt>, // Store BigInt directly, assuming None isn't needed after generation

    // public keys (Xj = uj*G for each Pj)
    pub big_x_j: Vec<EdwardsPoint>, // Use concrete EdwardsPoint type

    // used for test assertions (may be discarded)
    pub eddsa_pub: EdwardsPoint, // Use concrete EdwardsPoint type

    // Removed ECDSA fields: local_pre_params, n_tilde_j, h1j, h2j, paillier_pks
}

impl LocalPartySaveData {
    // Creates a new LocalPartySaveData with vectors initialized for party_count
    // Requires initial secret values.
    pub fn new(party_count: usize, secrets: LocalSecrets) -> Self {
        LocalPartySaveData {
            local_secrets: secrets,
            ks: vec![BigInt::default(); party_count],
            big_x_j: vec![EdwardsPoint::default(); party_count], // Requires Default impl for EdwardsPoint
            // Initialize eddsa_pub with a default/identity value
            eddsa_pub: EdwardsPoint::default(), // Requires Default impl for EdwardsPoint
        }
    }

    // Creates an empty/default save data structure (useful for initialization before rounds)
    pub fn new_empty(party_count: usize) -> Self {
        LocalPartySaveData {
            local_secrets: LocalSecrets {
                xi: BigInt::default(), // Initialize with default
                share_id: BigInt::default(),
            },
            ks: vec![BigInt::default(); party_count],
            big_x_j: vec![EdwardsPoint::default(); party_count],
            eddsa_pub: EdwardsPoint::default(),
        }
    }

    // BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
    pub fn build_subset(&self, sorted_ids: &SortedPartyIDs) -> Result<Self, Box<dyn Error>> {
        let signer_count = sorted_ids.len();
        let mut keys_to_indices: HashMap<&BigInt, usize> = HashMap::with_capacity(self.ks.len());
        for (j, k) in self.ks.iter().enumerate() {
             keys_to_indices.insert(k, j);
        }

        // Create new data structure with the signer count
        let mut new_data = Self::new_empty(signer_count);

        // Copy common secret and public key data
        new_data.local_secrets = self.local_secrets.clone();
        new_data.eddsa_pub = self.eddsa_pub.clone(); // EdwardsPoint should be Clone

        for (j, id) in sorted_ids.iter().enumerate() {
            // id.key() corresponds to the BigInt share_id (kj)
            let saved_idx = keys_to_indices.get(id.key()).ok_or_else(|| {
                format!("BuildLocalSaveDataSubset: unable to find party key {:?} in the local save data", id.key())
            })?;

            // Clone data from the original index into the new structure
            new_data.ks[j] = self.ks[*saved_idx].clone();
            new_data.big_x_j[j] = self.big_x_j[*saved_idx].clone(); // EdwardsPoint should be Clone
            // Removed copying of ECDSA fields (n_tilde_j, h1j, h2j, paillier_pks)
        }

        Ok(new_data)
    }

    // Add implementation for original_index if not already present
    // (It was added in local_party.rs previously, might be better placed here)
    pub fn original_index(&self) -> Result<usize, String> {
        let share_id = &self.local_secrets.share_id;

        for (j, k) in self.ks.iter().enumerate() {
             if k == share_id {
                 return Ok(j);
             }
        }
        Err("A party index could not be recovered from Ks".to_string())
    }
}

// Note: Serialization/Deserialization for LocalPartySaveData
// needs handling for EdwardsPoint (e.g., using serde_bytes for compressed representation
// or a wrapper struct that implements Serialize/Deserialize).
// The derive(Serialize, Deserialize) might fail depending on EdwardsPoint implementation.
