// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// EDDSA Keygen round logic (ported from Go)

use num_bigint::BigInt;
// use crate::eddsa::keygen::{LocalPartySaveData, LocalTempData};
// use crate::tss::{Parameters, Message, PartyID, Error};

const TASK_NAME: &str = "eddsa-keygen";

pub struct BaseRound<'a> {
    pub params: &'a Parameters, // TODO: Replace with actual Parameters
    pub save: &'a mut LocalPartySaveData, // TODO: Replace with actual LocalPartySaveData
    pub temp: &'a mut LocalTempData, // TODO: Replace with actual LocalTempData
    // pub out: Sender<Message>,
    // pub end: Sender<LocalPartySaveData>,
    pub ok: Vec<bool>,
    pub started: bool,
    pub number: usize,
}

pub struct Round1<'a> {
    pub base: BaseRound<'a>,
}

pub struct Round2<'a> {
    pub round1: Round1<'a>,
}

pub struct Round3<'a> {
    pub round2: Round2<'a>,
}

impl<'a> BaseRound<'a> {
    pub fn params(&self) -> &Parameters {
        self.params
    }
    pub fn round_number(&self) -> usize {
        self.number
    }
    pub fn can_proceed(&self) -> bool {
        if !self.started {
            return false;
        }
        self.ok.iter().all(|&ok| ok)
    }
    pub fn waiting_for(&self) -> Vec<&PartyID> {
        // TODO: Implement using self.params.parties().ids()
        vec![]
    }
    pub fn wrap_error(&self, _err: &str, _culprits: &[&PartyID]) -> Error {
        // TODO: Implement error wrapping
        Error {}
    }
    pub fn reset_ok(&mut self) {
        for ok in &mut self.ok {
            *ok = false;
        }
    }
    pub fn get_ssid(&self) -> Option<Vec<u8>> {
        // Implement using curve params and party ids
        Some(vec![1, 2, 3]) // Example implementation
    }
}

// Placeholder types for porting
pub struct Parameters;
pub struct LocalPartySaveData;
pub struct LocalTempData { pub ssid_nonce: BigInt }
pub struct Message;
pub struct PartyID;
pub struct Error;
