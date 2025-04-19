use crate::crypto::paillier; // Import the actual paillier module
use crate::tss::party_id::{PartyID, SortedPartyIDs}; // Use actual types
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

// Placeholder for ECPoint type (to be replaced with real implementation)
pub struct ECPoint {
    pub x: BigInt,
    pub y: BigInt,
    // Add additional fields or methods if necessary
}

// --- Placeholders for Crypto Types (replace with actual types) ---
// TODO: Replace with actual Paillier private key type
// Placeholder PaillierPrivateKey removed

// TODO: Replace with actual Paillier public key type
// Placeholder PaillierPublicKey removed

// TODO: Replace with actual EdDSA Point/Scalar types from the chosen library
// (e.g., from curve25519-dalek or ed25519-dalek)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdDSASecretShareScalar { // Corresponds to Go's Xi (*big.Int scalar)
    pub scalar: BigInt, // Or specific scalar type from the library
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdDSAPublicKeyPoint { // Corresponds to Go's *crypto.ECPoint
    pub point: Vec<u8>, // Or specific point type from the library (compressed or full)
}
// --- End Placeholders ---

#[derive(Debug, Clone /* Serialize, Deserialize */)] // Paillier keys might not be directly serializable
pub struct LocalPreParams {
    // Use the actual Paillier PrivateKey type
    pub paillier_sk: Option<paillier::PrivateKey>, // ski
    pub n_tilde_i: Option<BigInt>,
    pub h1i: Option<BigInt>,
    pub h2i: Option<BigInt>,
    pub alpha: Option<BigInt>,
    pub beta: Option<BigInt>,
    // Note: p and q are already fields within paillier::PrivateKey
    // Keep these separate based on Go struct, might be redundant?
    pub p: Option<BigInt>, // Paillier prime p (from SK)
    pub q: Option<BigInt>, // Paillier prime q (from SK)
}

impl LocalPreParams {
    // Validation now needs to check fields inside paillier_sk if needed
    pub fn validate(&self) -> bool {
        self.paillier_sk.is_some() &&
        self.n_tilde_i.is_some() &&
        self.h1i.is_some() &&
        self.h2i.is_some()
    }

    // Validation now checks p and q from the actual paillier_sk
    pub fn validate_with_proof(&self) -> bool {
        self.validate() &&
        // self.paillier_sk.as_ref().map_or(false, |sk| sk.p.is_some() && sk.q.is_some()) && // p, q are not Option in actual SK
        self.alpha.is_some() &&
        self.beta.is_some() &&
        self.p.is_some() && // Keep checking the separate p, q as per original Go struct logic
        self.q.is_some()
        // We might also check self.p == self.paillier_sk.p etc. if desired
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSecrets {
    pub xi: Option<EdDSASecretShareScalar>,
    pub share_id: Option<BigInt>,
}

// Everything in LocalPartySaveData is saved locally when done
#[derive(Debug, Clone /* Serialize, Deserialize */)] // Paillier keys might not be directly serializable
pub struct LocalPartySaveData {
    // Embed PreParams and Secrets directly (Rust doesn't have Go's embedding)
    pub local_pre_params: LocalPreParams,
    pub local_secrets: LocalSecrets,

    // Original indexes (ki in signing preparation phase)
    pub ks: Vec<Option<BigInt>>,

    // n-tilde, h1, h2 for range proofs from other parties
    pub n_tilde_j: Vec<Option<BigInt>>,
    pub h1j: Vec<Option<BigInt>>,
    pub h2j: Vec<Option<BigInt>>,

    // Public keys (Xj = uj*G for each Pj)
    pub big_x_j: Vec<Option<EdDSAPublicKeyPoint>>, // Xj (public key shares)
    // Use the actual Paillier PublicKey type
    pub paillier_pks: Vec<Option<paillier::PublicKey>>, // pkj

    // Combined public key (may be discarded after verification)
    pub eddsa_pub: Option<EdDSAPublicKeyPoint>, // y (combined EdDSA public key)
}

impl LocalPartySaveData {
    // Creates a new LocalPartySaveData with vectors initialized for party_count
    pub fn new(party_count: usize) -> Self {
        LocalPartySaveData {
            local_pre_params: LocalPreParams {
                paillier_sk: None,
                n_tilde_i: None,
                h1i: None,
                h2i: None,
                alpha: None,
                beta: None,
                p: None, // Initialize the separate p, q
                q: None,
            },
            local_secrets: LocalSecrets {
                xi: None,
                share_id: None,
            },
            ks: vec![None; party_count],
            n_tilde_j: vec![None; party_count],
            h1j: vec![None; party_count],
            h2j: vec![None; party_count],
            big_x_j: vec![None; party_count],
            paillier_pks: vec![None; party_count],
            eddsa_pub: None,
        }
    }

    // BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
    pub fn build_subset(&self, sorted_ids: &SortedPartyIDs) -> Result<Self, Box<dyn Error>> {
        let signer_count = sorted_ids.len();
        let mut keys_to_indices: HashMap<&BigInt, usize> = HashMap::with_capacity(self.ks.len());
        for (j, k_opt) in self.ks.iter().enumerate() {
            if let Some(k) = k_opt {
                keys_to_indices.insert(k, j);
            } else {
                // Handle error: Found None in Ks, which might indicate incomplete data
                return Err(From::from("BuildLocalSaveDataSubset: Found None in source Ks list"));
            }
        }

        let mut new_data = Self::new(signer_count);
        // Cloning LocalPreParams and LocalPartySaveData now clones the actual paillier keys
        new_data.local_pre_params = self.local_pre_params.clone();
        new_data.local_secrets = self.local_secrets.clone();
        new_data.eddsa_pub = self.eddsa_pub.clone();

        for (j, id) in sorted_ids.iter().enumerate() {
            // id.key corresponds to the BigInt share_id (kj)
            let saved_idx = keys_to_indices.get(id.key()).ok_or_else(|| {
                format!("BuildLocalSaveDataSubset: unable to find party key {:?} in the local save data", id.key())
            })?;

            // Clone data from the original index into the new structure
            new_data.ks[j] = self.ks[*saved_idx].clone();
            new_data.n_tilde_j[j] = self.n_tilde_j[*saved_idx].clone();
            new_data.h1j[j] = self.h1j[*saved_idx].clone();
            new_data.h2j[j] = self.h2j[*saved_idx].clone();
            new_data.big_x_j[j] = self.big_x_j[*saved_idx].clone();
            new_data.paillier_pks[j] = self.paillier_pks[*saved_idx].clone(); // Clones Option<paillier::PublicKey>
        }

        Ok(new_data)
    }

    // Add implementation for original_index if not already present
    // (It was added in local_party.rs previously, might be better placed here)
    pub fn original_index(&self) -> Result<usize, String> {
        let share_id = self.local_secrets.share_id.as_ref()
            .ok_or_else(|| "Missing share_id in local secrets".to_string())?;

        for (j, k_opt) in self.ks.iter().enumerate() {
            if let Some(k) = k_opt {
                if k == share_id {
                    return Ok(j);
                }
            }
        }
        Err("A party index could not be recovered from Ks".to_string())
    }
}

// Note: Serialization/Deserialization for LocalPreParams and LocalPartySaveData
// might need custom implementations (e.g., using serde_bytes or custom serialize/deserialize)
// if the underlying paillier::PrivateKey/PublicKey don't derive Serialize/Deserialize
// or if a specific byte format is needed for the BigInts within them.
// Commented out derive(Serialize, Deserialize) for now.
