use std::{
    fs,
    path::{PathBuf},
    error::Error, // Standard error trait
};
use serde::{Deserialize, Serialize}; // Still needed for JSON

// Use keygen save data
use crate::eddsa::keygen::save_data::LocalPartySaveData;
// Use tss party id
use crate::tss::party_id::{PartyID, SortedPartyIDs};

// Constants analogous to Go version
pub const TEST_PARTICIPANTS: usize = 4; // Example value, match Go if applicable
pub const TEST_THRESHOLD: usize = TEST_PARTICIPANTS / 2;

const TEST_FIXTURE_DIR_FORMAT: &str = "../../test/_eddsa_fixtures"; // Adjusted for EdDSA
const TEST_FIXTURE_FILE_FORMAT: &str = "keygen_data_{}.json";

// Helper function to get the path to a fixture file
fn make_test_fixture_file_path(party_index: usize) -> PathBuf {
    // Using std::env::current_dir() or file!() might be fragile depending on where tests are run.
    // Consider using manifest_dir (CARGO_MANIFEST_DIR env var) or defining paths relative to the workspace root.
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
) -> Result<(Vec<LocalPartySaveData>, SortedPartyIDs), Box<dyn Error>> { // Use Box<dyn Error>
    let mut keys = Vec::with_capacity(qty);
    let start = optional_start.unwrap_or(0);
    let mut party_ids_unsorted: Vec<PartyID> = Vec::with_capacity(qty); // Use actual PartyID

    for i in start..(start + qty) {
        let fixture_path = make_test_fixture_file_path(i);
        let bz = fs::read(&fixture_path).map_err(|e| {
             // Use format! to create a String and then Box::from to convert to Box<dyn Error>
             Box::<dyn Error>::from(format!(
                "Could not open the test fixture for party {} in {}: {}. Run keygen tests first.",
                i, fixture_path.display(), e
             ))
        })?;

        let key: LocalPartySaveData = serde_json::from_slice(&bz).map_err(|e| {
             Box::<dyn Error>::from(format!(
                "Could not unmarshal fixture data for party {} at {}: {}",
                i, fixture_path.display(), e
             ))
        })?;

        // TODO: If using ECPoint types that need curve info set after deserialization,
        // add that logic here, similar to Go's `kbxj.SetCurve(tss.Edwards())`.
        // Example: key.big_x_j.iter_mut().for_each(|p| p.set_curve(...));

        // Extract the share_id for creating the PartyID
        // Assuming LocalSecrets fields are not Options anymore after save_data update
        let share_id = key.local_secrets.share_id.clone();

        // Assuming PartyID::new exists and takes these arguments
        let moniker = format!("{}", i + 1);
        // Use actual PartyID constructor
        party_ids_unsorted.push(PartyID::new(&i.to_string(), &moniker, share_id)?); // Assuming new can fail
        keys.push(key);
    }

    // Sort party IDs - Assuming PartyID implements Ord based on its key field
    let sorted_pids = SortedPartyIDs::from_unsorted(&party_ids_unsorted)?;

    // Sort keys based on share_id (which should match party ID key)
    keys.sort_by(|a, b| {
        a.local_secrets.share_id.cmp(&b.local_secrets.share_id)
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
