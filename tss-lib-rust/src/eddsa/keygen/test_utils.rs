use crate::eddsa::keygen::save_data::LocalPartySaveData; // Use the actual struct
use crate::tss::party_id::{PartyID, SortedPartyIDs}; // Use actual PartyID from tss module
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Once, // For lazy static initialization if needed
};

// Constants analogous to Go version
pub const TEST_PARTICIPANTS: usize = 4; // Example value, match Go if applicable
pub const TEST_THRESHOLD: usize = TEST_PARTICIPANTS / 2;

const TEST_FIXTURE_DIR_FORMAT: &str = "../../test/_eddsa_fixtures"; // Adjusted for EdDSA
const TEST_FIXTURE_FILE_FORMAT: &str = "keygen_data_{}.json";

// Helper function to get the path to a fixture file
fn make_test_fixture_file_path(party_index: usize) -> PathBuf {
    // Using std::env::current_dir() might be fragile depending on where tests are run.
    // Consider using manifest_dir or defining paths relative to the workspace root.
    // For simplicity, mimicking the Go relative path structure for now.
    let mut path = PathBuf::from(file!()); // Gets the path to *this* source file
    path.pop(); // Remove filename -> src/eddsa/keygen
    path.pop(); // -> src/eddsa
    path.pop(); // -> src
    path.pop(); // -> tss-lib-rust
    path.push(TEST_FIXTURE_DIR_FORMAT);
    path.push(format!(TEST_FIXTURE_FILE_FORMAT, party_index));
    path
}

// Loads keygen test fixtures for a specified quantity of parties.
pub fn load_keygen_test_fixtures(
    qty: usize,
    optional_start: Option<usize>,
) -> Result<(Vec<LocalPartySaveData>, SortedPartyIDs), String> {
    let mut keys = Vec::with_capacity(qty);
    let start = optional_start.unwrap_or(0);
    let mut party_ids_unsorted: Vec<PartyID> = Vec::with_capacity(qty); // Use actual PartyID

    for i in start..(start + qty) {
        let fixture_path = make_test_fixture_file_path(i);
        let bz = fs::read(&fixture_path).map_err(|e| {
            format!(
                "Could not open the test fixture for party {} in {}: {}. Run keygen tests first.",
                i, fixture_path.display(), e
            )
        })?;

        let key: LocalPartySaveData = serde_json::from_slice(&bz).map_err(|e| {
            format!(
                "Could not unmarshal fixture data for party {} at {}: {}",
                i, fixture_path.display(), e
            )
        })?;

        // TODO: Perform any necessary post-deserialization setup for EdDSA keys/points
        // Example: key.public_key.set_curve(...); if using a curve point object

        // Extract the share_id for creating the PartyID
        let share_id = key.local_secrets.share_id.clone().ok_or_else(|| {
            format!("Missing share_id in fixture for party {} at {}", i, fixture_path.display())
        })?;

        // Assuming PartyID::new exists and takes these arguments
        // The actual PartyID might store index differently or require context
        let moniker = format!("{}", i + 1);
        party_ids_unsorted.push(PartyID::new(&i.to_string(), &moniker, share_id)); // Use actual constructor
        keys.push(key);
    }

    // Sort party IDs - Assuming PartyID implements Ord based on its key field
    party_ids_unsorted.sort(); // Use the derived Ord for sorting
    let sorted_pids: SortedPartyIDs = party_ids_unsorted; // Use actual SortedPartyIDs (likely Vec<PartyID>)

    keys.sort_by(|a, b| {
        let a_id = a.local_secrets.share_id.as_ref().unwrap_or(&BigInt::from(0));
        let b_id = b.local_secrets.share_id.as_ref().unwrap_or(&BigInt::from(0));
        a_id.cmp(b_id)
    });

    Ok((keys, sorted_pids))
}

// TODO: Implement `load_keygen_test_fixtures_random_set` if needed.
// It involves randomly selecting a subset of fixtures.

// TODO: Implement `load_n_tilde_h1_h2_from_test_fixture` if these values are relevant for EdDSA keygen
// and stored in the fixtures (e.g., `key.local_pre_params.n_tilde_i`).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eddsa::keygen::save_data::LocalPartySaveData; // Make sure it's in scope
    use crate::tss::party_id::PartyID; // Ensure actual PartyID is used in tests

    // Basic test to check if loading fixtures works (requires fixtures to exist)
    #[test]
    #[ignore] // Ignored because it depends on external fixture files
    fn test_load_fixtures() {
        let qty = TEST_PARTICIPANTS;
        let result = load_keygen_test_fixtures(qty, None);

        match result {
            Ok((keys, pids)) => {
                assert_eq!(keys.len(), qty);
                assert_eq!(pids.len(), qty);
                println!("Loaded {} keys and PIDs successfully.", qty);
                for i in 0..pids.len() - 1 {
                    assert!(pids[i] <= pids[i+1]); // Check sorting using Ord
                    assert!(keys[i].local_secrets.share_id.is_some());
                    assert!(keys[i+1].local_secrets.share_id.is_some());
                    // Compare PartyID key with saved share_id
                    assert_eq!(&keys[i].local_secrets.share_id.as_ref().unwrap(), pids[i].key());
                    assert!(keys[i].local_secrets.share_id <= keys[i+1].local_secrets.share_id);
                }
                if !pids.is_empty() {
                   assert_eq!(&keys[qty-1].local_secrets.share_id.as_ref().unwrap(), pids[qty-1].key());
                }
            }
            Err(e) => {
                // Fail the test if loading fails, but provide a helpful message
                panic!("Failed to load keygen fixtures: {}. Ensure fixtures exist in '{}' and keygen was run.", e, make_test_fixture_file_path(0).parent().unwrap().display());
            }
        }
    }

     #[test]
     fn test_fixture_path_creation() {
        // Simple check for path format - doesn't guarantee correctness on all systems
        let path = make_test_fixture_file_path(0);
        println!("Generated fixture path: {}", path.display());
        assert!(path.ends_with("_eddsa_fixtures/keygen_data_0.json"));
     }
}
