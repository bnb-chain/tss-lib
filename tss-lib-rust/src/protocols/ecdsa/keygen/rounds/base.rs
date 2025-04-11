// src/protocols/ecdsa/keygen/rounds/base.rs

use crate::tss::party_id::PartyID;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Base structure providing common round functionality.
#[derive(Debug)] // Add Debug trait
pub(crate) struct BaseRound {
    round_num: i32,
    ok: Mutex<Vec<bool>>, // Tracks which parties' messages have been processed for the current `update` step
    started: AtomicBool,
}

impl BaseRound {
    pub fn new(round_num: i32, party_count: usize) -> Self {
        Self {
            round_num,
            ok: Mutex::new(vec![false; party_count]),
            started: AtomicBool::new(false),
        }
    }

    pub fn round_number(&self) -> i32 {
        self.round_num
    }

    pub fn started(&self) -> bool {
        self.started.load(Ordering::Relaxed)
    }

    pub fn set_started(&self) {
        self.started.store(true, Ordering::Relaxed);
    }

    /// This should only be called by `next_round` when transitioning.
    pub fn set_started_unwrapped(&self) {
         // This assumes the transition logic ensures no races.
        self.started.store(false, Ordering::Relaxed);
    }

    pub fn reset_ok(&self) {
        let mut ok_guard = self.ok.lock().expect("OK vector lock poisoned");
        for i in 0..ok_guard.len() {
            ok_guard[i] = false;
        }
    }

    pub fn set_ok(&self, party_index: usize) {
        let mut ok_guard = self.ok.lock().expect("OK vector lock poisoned");
        if party_index < ok_guard.len() {
            ok_guard[party_index] = true;
        } else {
            // Log or handle error: index out of bounds
             log::error!("set_ok index out of bounds: {} >= {}", party_index, ok_guard.len());
        }
    }

    pub fn is_ok(&self, party_index: usize) -> bool {
        let ok_guard = self.ok.lock().expect("OK vector lock poisoned");
        party_index < ok_guard.len() && ok_guard[party_index]
    }

    /// Returns a copy of the current `ok` vector.
    pub fn get_ok_vec(&self) -> Vec<bool> {
        self.ok.lock().expect("OK vector lock poisoned").clone()
    }

    /// Helper to determine which parties are still needed for the round to proceed.
    pub fn waiting_for(&self, all_parties: &[std::sync::Arc<PartyID>]) -> Vec<PartyID> {
        let ok_guard = self.ok.lock().expect("OK vector lock poisoned");
        let mut waiting_list = Vec::new();
        for (idx, party) in all_parties.iter().enumerate() {
             // Check if the index is within bounds of the ok vector AND if the party is marked as NOT ok
             if idx < ok_guard.len() && !ok_guard[idx] {
                 waiting_list.push(party.as_ref().clone());
             } else if idx >= ok_guard.len() {
                 // This case should ideally not happen if ok vector is sized correctly
                 log::warn!("Party index {} out of bounds for ok vector (len {}), assuming waiting.", idx, ok_guard.len());
                 waiting_list.push(party.as_ref().clone());
             }
        }
        waiting_list
    }
} 