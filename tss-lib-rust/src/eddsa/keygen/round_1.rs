// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// EDDSA Keygen round 1 logic (ported from Go)

use num_bigint::BigInt;
use crate::eddsa::keygen::save_data::LocalPartySaveData;
use crate::eddsa::keygen::local_party::{LocalTempData, LocalMessageStore, HashCommitment, Vs, Shares, HashDeCommitment};
use crate::eddsa::keygen::messages::KGRound1Message;
use crate::tss::params::Parameters;
use crate::tss::party_id::PartyID;
use rand::Rng;
// use crate::eddsa::keygen::rounds::{BaseRound, Round2};

pub struct Error;
pub struct ParsedMessage;

pub struct BaseRound<'a> {
    pub params: &'a Parameters,
    pub save: &'a mut LocalPartySaveData,
    pub temp: &'a mut LocalTempData,
    pub ok: Vec<bool>,
    pub started: bool,
    pub number: usize,
}

pub struct Round1<'a> {
    pub base: BaseRound<'a>,
}

impl<'a> Round1<'a> {
    pub fn new(
        params: &'a Parameters,
        save: &'a mut LocalPartySaveData,
        temp: &'a mut LocalTempData,
    ) -> Self {
        let party_count = 3; // TODO: params.party_count()
        Round1 {
            base: BaseRound {
                params,
                save,
                temp,
                ok: vec![false; party_count],
                started: false,
                number: 1,
            },
        }
    }

    pub fn start(&mut self) -> Result<(), Error> {
        if self.base.started {
            // TODO: Return error for already started
            return Ok(());
        }
        self.base.number = 1;
        self.base.started = true;
        for ok in &mut self.base.ok {
            *ok = false;
        }
        // Set ssid_nonce (random big int)
        let mut rng = rand::thread_rng();
        let ssid_nonce = BigInt::from(rng.gen::<u64>());
        self.base.temp.ssid_nonce = Some(ssid_nonce.clone());
        // Compute ssid
        self.base.temp.ssid = Some(self.base.get_ssid().unwrap_or_default());
        // 1. calculate "partial" key share ui (random positive int)
        let ui = self.base.params.random_positive_int();
        self.base.temp.ui = Some(ui.clone());
        // 2. compute the vss shares (stub)
        // TODO: Use a VSS crate or port vss::Create
        // let (vs, shares) = vss_create(...);
        // self.base.temp.vs = Some(vs);
        // self.base.temp.shares = Some(shares);
        // self.base.save.ks = ...;
        // 3. make commitment (stub)
        // TODO: Use EC point flattening and hash commitment
        // let p_g_flat = flatten_ec_points(&vs);
        // let cmt = hash_commitment(&p_g_flat);
        // self.base.temp.de_commit_poly_g = Some(cmt.decommitment);
        // Store shareID, vs, shares, de_commit_poly_g (stub)
        // TODO: Use real party index and IDs
        // self.base.save.share_id = ...;
        // Create and store KGRound1Message
        let commitment = vec![]; // TODO: Use real commitment
        let msg = KGRound1Message { commitment };
        // TODO: Get real party index
        let i = 0;
        self.base.temp.local_message_store.kg_round1_messages[i] = Some(msg);
        // TODO: Broadcast the message (e.g., via channel)
        Ok(())
    }

    pub fn can_accept(&self, _msg: &ParsedMessage) -> bool {
        // TODO: Check if message is KGRound1Message and is broadcast
        false
    }

    pub fn update(&mut self) -> Result<bool, Error> {
        let mut ret = true;
        for (j, msg) in self.base.temp.local_message_store.kg_round1_messages.iter().enumerate() {
            if self.base.ok[j] {
                continue;
            }
            if msg.is_none() || !self.can_accept(&ParsedMessage) {
                ret = false;
                continue;
            }
            // TODO: vss check in round 2
            self.base.ok[j] = true;
        }
        Ok(ret)
    }

    pub fn next_round(self) -> Round2<'a> {
        // Reset started for next round
        // TODO: Implement transition to round 2
        Round2 { round1: self }
    }
}

pub struct Round2<'a> {
    pub round1: Round1<'a>,
}

// Placeholder types for porting
pub struct Message;
