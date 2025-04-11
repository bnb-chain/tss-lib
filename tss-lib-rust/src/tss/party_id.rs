// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/tss/party_id.go

use crate::common::test_utils::generate_random_bigint_in_range;
use num_bigint_dig::{{BigInt, Sign}};
use num_traits::Zero;
use serde::{{Deserialize, Serialize}};
use std::{{
    cmp::Ordering,
    collections::HashSet,
    fmt,
    hash::{Hash, Hasher},
}};

/// Represents a participant in the TSS protocol rounds.
/// Contains the message wrapper part for serialization and an index assigned after sorting.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyID {
    // Corresponds to tss_minimal.proto MessageWrapper_PartyID
    pub id: String,      // A unique string ID for the party (derived from key)
    pub moniker: String, // A human-readable identifier
    #[serde(with = "crate::serde_support::bigint_bytes")]
    pub key: BigInt,     // A unique identifying key (e.g., from Paillier Pk)
    // ---
    pub index: i32,      // Assigned zero-based index after sorting parties by key
}

impl PartyID {
    /// Creates a new `PartyID`.
    /// The `key` should remain consistent between runs for each party.
    /// `index` is initialized to -1 and assigned later by `sort_party_ids`.
    pub fn new(id: String, moniker: String, key: BigInt) -> Self {
        Self {
            id,
            moniker,
            key,
            index: -1, // Not known until sorted
        }
    }

    /// Validates the basic properties of the PartyID.
    pub fn validate_basic(&self) -> bool {
         !self.key.is_zero() && self.index >= 0 // Key should not be zero, index should be non-negative
    }
}

// --- Trait Implementations ---

// Custom comparison based *only* on the `key` field for sorting.
impl Ord for PartyID {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl PartialOrd for PartyID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Equality based *only* on the `key` field.
impl PartialEq for PartyID {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for PartyID {}

// Hashing based *only* on the `key` field.
impl Hash for PartyID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl fmt::Display for PartyID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{},{}}}", self.index, self.moniker)
    }
}

// --- Sorting and Utility Functions ---

/// Sorts a slice of `PartyID`s in place by their `key` and assigns indices.
///
/// # Arguments
/// * `ids` - A mutable slice of `PartyID`s to sort.
/// * `start_at` - Optional starting index (defaults to 0).
pub fn sort_party_ids(ids: &mut [PartyID], start_at: Option<i32>) {
    ids.sort_unstable(); // Sorts based on the Ord impl (key)
    let start_index = start_at.unwrap_or(0);
    for (i, id) in ids.iter_mut().enumerate() {
        id.index = start_index + i as i32;
    }
}

/// Finds a `PartyID` within a slice by its `key`.
pub fn find_party_by_key('a, ids: &'a [PartyID], key: &BigInt) -> Option<&'a PartyID> {
    ids.iter().find(|&p| &p.key == key)
}

/// Creates a new vector containing `PartyID`s from the input slice, excluding the specified one.
pub fn exclude_party(ids: &[PartyID], exclude: &PartyID) -> Vec<PartyID> {
    ids.iter().filter(|&p| p != exclude).cloned().collect()
}

/// Converts a slice of `PartyID`s to a vector of their keys.
pub fn get_party_keys(ids: &[PartyID]) -> Vec<BigInt> {
    ids.iter().map(|p| p.key.clone()).collect()
}

/// Generates a list of mock `PartyID`s for tests, sorts them, and assigns indices.
#[cfg(feature = "test_utils")]
pub fn generate_test_party_ids(count: usize, start_at: Option<i32>) -> Vec<PartyID> {
    use rand::thread_rng;

    let start_index = start_at.unwrap_or(0);
    let mut rng = thread_rng();
    let base_key = generate_random_bigint_in_range(
        &mut rng,
        &BigInt::from(1u32) << 255,
        &(&BigInt::from(1u32) << 256) - BigInt::one(),
    );

    // Ensure unique keys by using a HashSet during generation
    let mut keys = HashSet::new();
    let mut ids = Vec::with_capacity(count);

    while ids.len() < count {
         // Generate slightly different keys for determinism, ensure uniqueness
         let offset = BigInt::from(ids.len() as i32);
         let key = &base_key + offset; // Simple offset for tests

        if keys.insert(key.clone()) {
            let i = ids.len() as i32 + start_index;
            ids.push(PartyID {
                id: format!("id_{}", i),
                moniker: format!("P[{}]"), i),
                key,
                index: -1, // Will be set by sorting
            });
        }
    }

    sort_party_ids(&mut ids, start_at);
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_utils::generate_random_bigint_in_range;
    use rand::thread_rng;

    #[test]
    fn test_party_id_validate_basic() {
        let key1 = BigInt::from(123);
        let mut p1 = PartyID::new("p1".to_string(), "Moniker1".to_string(), key1.clone());
        assert!(!p1.validate_basic()); // Index is -1

        p1.index = 0;
        assert!(p1.validate_basic());

        let mut p0 = PartyID::new("p0".to_string(), "Moniker0".to_string(), BigInt::zero());
        p0.index = 0;
        assert!(!p0.validate_basic()); // Key is zero
    }

    #[test]
    fn test_party_id_sorting() {
        let mut ids = vec![
            PartyID::new("p3".to_string(), "P3".to_string(), BigInt::from(300)),
            PartyID::new("p1".to_string(), "P1".to_string(), BigInt::from(100)),
            PartyID::new("p2".to_string(), "P2".to_string(), BigInt::from(200)),
        ];

        sort_party_ids(&mut ids, None);

        assert_eq!(ids[0].key, BigInt::from(100));
        assert_eq!(ids[0].index, 0);
        assert_eq!(ids[1].key, BigInt::from(200));
        assert_eq!(ids[1].index, 1);
        assert_eq!(ids[2].key, BigInt::from(300));
        assert_eq!(ids[2].index, 2);

        // Test sorting with start_at
        sort_party_ids(&mut ids, Some(10));
        assert_eq!(ids[0].index, 10);
        assert_eq!(ids[1].index, 11);
        assert_eq!(ids[2].index, 12);
    }

    #[test]
    fn test_party_id_equality_and_hashing() {
        let p1a = PartyID { id: "a".into(), moniker: "A".into(), key: BigInt::from(100), index: 0 };
        let p1b = PartyID { id: "b".into(), moniker: "B".into(), key: BigInt::from(100), index: 1 };
        let p2 = PartyID { id: "c".into(), moniker: "C".into(), key: BigInt::from(200), index: 2 };

        assert_eq!(p1a, p1b); // Equal based on key
        assert_ne!(p1a, p2);

        let mut set = HashSet::new();
        assert!(set.insert(p1a.clone()));
        assert!(!set.insert(p1b.clone())); // Fails because key is the same
        assert!(set.insert(p2.clone()));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_find_party_by_key() {
        let mut ids = vec![
            PartyID::new("p3".to_string(), "P3".to_string(), BigInt::from(300)),
            PartyID::new("p1".to_string(), "P1".to_string(), BigInt::from(100)),
            PartyID::new("p2".to_string(), "P2".to_string(), BigInt::from(200)),
        ];
        sort_party_ids(&mut ids, None);

        let key_to_find = BigInt::from(200);
        let found = find_party_by_key(&ids, &key_to_find);
        assert!(found.is_some());
        assert_eq!(found.unwrap().key, key_to_find);
        assert_eq!(found.unwrap().moniker, "P2");

        let key_not_found = BigInt::from(400);
        assert!(find_party_by_key(&ids, &key_not_found).is_none());
    }

    #[test]
    fn test_exclude_party() {
        let mut ids = vec![
            PartyID::new("p3".to_string(), "P3".to_string(), BigInt::from(300)),
            PartyID::new("p1".to_string(), "P1".to_string(), BigInt::from(100)),
            PartyID::new("p2".to_string(), "P2".to_string(), BigInt::from(200)),
        ];
        sort_party_ids(&mut ids, None);

        let party_to_exclude = ids[1].clone(); // Exclude P2 (key 200)
        let excluded = exclude_party(&ids, &party_to_exclude);

        assert_eq!(excluded.len(), 2);
        assert_eq!(excluded[0].key, BigInt::from(100));
        assert_eq!(excluded[1].key, BigInt::from(300));
    }

     #[test]
     #[cfg(feature = "test_utils")]
     fn test_generate_test_party_ids() {
         let count = 5;
         let ids = generate_test_party_ids(count, Some(1)); // Start index at 1

         assert_eq!(ids.len(), count);
         let mut last_key = BigInt::zero();
         let mut keys = HashSet::new();
         for i in 0..count {
             assert_eq!(ids[i].index, (i + 1) as i32);
             assert!(ids[i].key > last_key); // Check sorted
             assert!(keys.insert(ids[i].key.clone())); // Check unique keys
             last_key = ids[i].key.clone();
         }
     }
} 