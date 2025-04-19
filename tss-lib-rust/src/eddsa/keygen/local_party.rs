// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Implements Party
// Implements Display

use std::fmt;
use std::sync::mpsc::Sender;
use num_bigint::BigInt;
use crate::eddsa::keygen::messages::{KGRound1Message, KGRound2Message1, KGRound2Message2};
use crate::eddsa::keygen::save_data::LocalPartySaveData;
use crate::tss::params::Parameters;
use crate::tss::party_id::PartyID;

// TODO: Replace these with actual imports or crate equivalents
// use crate::tss::{BaseParty, Parameters, Message, ParsedMessage, Party, Error, PartyID};
// use crate::common;
// use crate::crypto::commitments as cmt;
// use crate::crypto::vss;

pub struct LocalParty {
    // pub base_party: BaseParty, // TODO: implement or import
    pub params: Box<Parameters>, // TODO: implement or import
    pub temp: LocalTempData,
    pub data: LocalPartySaveData,
    pub out: Option<Sender<Message>>, // outbound messaging
    pub end: Option<Sender<LocalPartySaveData>>, // end signal
}

pub struct LocalMessageStore {
    pub kg_round1_messages: Vec<Option<KGRound1Message>>,
    pub kg_round2_message1s: Vec<Option<KGRound2Message1>>,
    pub kg_round2_message2s: Vec<Option<KGRound2Message2>>,
    // pub kg_round3_messages: Vec<Option<KGRound3Message>>, // If defined
}

pub struct LocalTempData {
    pub local_message_store: LocalMessageStore,
    // temp data (thrown away after keygen)
    pub ui: Option<BigInt>, // used for tests
    pub kgcs: Vec<Option<HashCommitment>>,
    pub vs: Option<Vs>,
    pub shares: Option<Shares>,
    pub de_commit_poly_g: Option<HashDeCommitment>,
    pub ssid: Option<Vec<u8>>,
    pub ssid_nonce: Option<BigInt>,
}

pub struct Message; // TODO: Replace with actual Message struct
pub struct ParsedMessage; // TODO: Replace with actual ParsedMessage struct

impl LocalPartySaveData {
    pub fn new(_party_count: usize) -> Self {
        // TODO: Implement actual initialization logic
        LocalPartySaveData {}
    }
}

// Enum to represent all possible keygen messages for easier handling
pub enum KeygenMessage {
    Round1 { msg: KGRound1Message, from_idx: usize },
    Round2_1 { msg: KGRound2Message1, from_idx: usize },
    Round2_2 { msg: KGRound2Message2, from_idx: usize },
    // Add Round3 variant if needed
}

impl LocalParty {
    pub fn new(
        params: Box<Parameters>,
        out: Option<Sender<Message>>,
        end: Option<Sender<LocalPartySaveData>>,
    ) -> Self {
        let party_count = 3; // TODO: Replace with params.party_count()
        let data = LocalPartySaveData::new(party_count);
        let temp = LocalTempData {
            local_message_store: LocalMessageStore {
                kg_round1_messages: vec![None; party_count],
                kg_round2_message1s: vec![None; party_count],
                kg_round2_message2s: vec![None; party_count],
                // kg_round3_messages: vec![None; party_count], // If defined
            },
            ui: None,
            kgcs: vec![None; party_count],
            vs: None,
            shares: None,
            de_commit_poly_g: None,
            ssid: None,
            ssid_nonce: None,
        };
        LocalParty {
            params,
            temp,
            data,
            out,
            end,
        }
    }

    pub fn first_round(&self) -> Option<Round1> {
        Some(Round1::new(&self.params, &mut self.data, &mut self.temp))
    }

    pub fn start(&mut self) -> Result<(), Error> {
        let mut round1 = self.first_round().ok_or(Error)?;
        round1.start()?;
        Ok(())
    }

    pub fn update(&mut self, _msg: ParsedMessage) -> Result<bool, Error> {
        // TODO: Implement BaseUpdate equivalent
        Ok(true)
    }

    pub fn update_from_bytes(&mut self, _wire_bytes: &[u8], _from: &PartyID, _is_broadcast: bool) -> Result<bool, Error> {
        // TODO: Implement ParseWireMessage and call update
        Ok(true)
    }

    pub fn validate_message(&self, _msg: &ParsedMessage) -> Result<bool, Error> {
        // TODO: Implement ValidateMessage logic
        Ok(true)
    }

    pub fn store_message(&mut self, msg: KeygenMessage) -> Result<bool, Error> {
        match msg {
            KeygenMessage::Round1 { msg, from_idx } => {
                if from_idx < self.temp.local_message_store.kg_round1_messages.len() {
                    self.temp.local_message_store.kg_round1_messages[from_idx] = Some(msg);
                    Ok(true)
                } else {
                    // TODO: Log warning about invalid index
                    Ok(false)
                }
            }
            KeygenMessage::Round2_1 { msg, from_idx } => {
                if from_idx < self.temp.local_message_store.kg_round2_message1s.len() {
                    self.temp.local_message_store.kg_round2_message1s[from_idx] = Some(msg);
                    Ok(true)
                } else {
                    // TODO: Log warning about invalid index
                    Ok(false)
                }
            }
            KeygenMessage::Round2_2 { msg, from_idx } => {
                if from_idx < self.temp.local_message_store.kg_round2_message2s.len() {
                    self.temp.local_message_store.kg_round2_message2s[from_idx] = Some(msg);
                    Ok(true)
                } else {
                    // TODO: Log warning about invalid index
                    Ok(false)
                }
            }
            // Add Round3 handling if needed
        }
    }

    pub fn party_id(&self) -> Option<&PartyID> {
        // TODO: Return self.params.party_id()
        None
    }

    pub fn string(&self) -> String {
        // TODO: Implement Display logic
        format!("LocalParty {{ ... }}")
    }
}

// Placeholder types for porting
pub struct Round; // TODO: Replace with actual Round struct
pub struct Error; // TODO: Replace with actual Error struct
pub struct HashCommitment; // TODO: Implement or import
pub struct Vs; // TODO: Implement or import
pub struct Shares; // TODO: Implement or import
pub struct HashDeCommitment; // TODO: Implement or import

impl fmt::Display for LocalParty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: Implement Display logic
        write!(f, "LocalParty {{ ... }}")
    }
}

// TODO: Implement Party trait for LocalParty
// TODO: Implement tests
