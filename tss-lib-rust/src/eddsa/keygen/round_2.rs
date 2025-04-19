// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// EDDSA Keygen round 2 logic (ported from Go)

use crate::eddsa::keygen::rounds::{Round, RoundCtx, RoundState, get_ssid, TASK_NAME};
use crate::eddsa::keygen::save_data::LocalPartySaveData;
use crate::eddsa::keygen::local_party::{LocalTempData, Message, ParsedMessage, TssError, PartyID, Parameters, KeygenMessageEnum};
use crate::eddsa::keygen::messages::{KGRound1Message, KGRound2Message1, KGRound2Message2, FacProof, ModProof}; // Import message types and placeholders
use crate::eddsa::keygen::dln_verifier::{DlnProofVerifier, HasDlnProofs}; // Import DLN verifier
use crate::eddsa::keygen::round_3::Round3; // Import Round3 for next_round
use crate::crypto::paillier; // Import actual paillier
use crate::tss::curve::{CurveName, get_curve_params, CurveParams}; // Import curve types
use crate::crypto::{fac_proof, mod_proof}; // Import actual proof functions

use num_bigint::BigInt;
use num_traits::Zero;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

// --- Placeholder Crypto Operations/Types --- //
// TODO: Replace with actual implementations

const PAILLIER_BITS_LEN: usize = 2048;

mod facproof {
    use super::{BigInt, Error, FacProof, PartyID};
    use rand::RngCore;
    pub fn new(
        _context: &[u8],
        _ec_params: &super::CurveParams, // Placeholder
        _n: &BigInt,
        _n_tilde_j: &BigInt,
        _h1j: &BigInt,
        _h2j: &BigInt,
        _p: &BigInt,
        _q: &BigInt,
        _rng: &mut dyn RngCore,
    ) -> Result<FacProof, Box<dyn Error>> {
        println!("Warning: Using placeholder facproof::new");
        Ok(FacProof(vec![4,5,6])) // Dummy proof bytes
    }
}

mod modproof {
    use super::{BigInt, Error, ModProof, PartyID};
    use rand::RngCore;
    pub fn new(
         _context: &[u8],
         _n: &BigInt,
         _p: &BigInt,
         _q: &BigInt,
         _rng: &mut dyn RngCore,
    ) -> Result<ModProof, Box<dyn Error>> {
        println!("Warning: Using placeholder modproof::new");
        Ok(ModProof(vec![7,8,9])) // Dummy proof bytes
    }
}

// Placeholder Paillier SK structure needed for proof generation
// Use the actual PrivateKey now
// use crate::eddsa::keygen::save_data::PaillierPrivateKey;

// TODO: Replace with actual EC Curve parameters for EdDSA (e.g., Ed25519)
pub struct CurveParams { pub p: BigInt, pub n: BigInt, pub gx: BigInt, pub gy: BigInt }
impl CurveParams { pub fn get() -> Self { CurveParams { p: BigInt::zero(), n: BigInt::from(100), gx: BigInt::zero(), gy: BigInt::zero() } } } // Dummy data

// Helper to construct KGRound2Message1 (P2P)
fn new_kg_round2_message1(
    to: &PartyID,
    from: &PartyID,
    share: &crate::eddsa::keygen::messages::VssShare,
    fac_proof: FacProof,
) -> Result<Message, Box<dyn Error>> {
    let content = KeygenMessageEnum::Round2_1(KGRound2Message1 {
        share: share.clone(),
        fac_proof: Some(fac_proof), // Assuming proof is always generated for now
    });
    // TODO: Implement actual wire byte serialization
    let wire_bytes = vec![0x02, 0x01]; // Placeholder serialization
    Ok(Message {
        content_type: TASK_NAME.to_string(),
        wire_bytes,
        from: from.clone(),
        is_broadcast: false,
    })
}

// Helper to construct KGRound2Message2 (Broadcast)
fn new_kg_round2_message2(
    from: &PartyID,
    decommitment: &crate::eddsa::keygen::messages::HashDeCommitment,
    mod_proof: ModProof,
) -> Result<Message, Box<dyn Error>> {
    let content = KeygenMessageEnum::Round2_2(KGRound2Message2 {
        decommitment: decommitment.clone(),
        mod_proof: Some(mod_proof), // Assuming proof is always generated for now
    });
    // TODO: Implement actual wire byte serialization
    let wire_bytes = vec![0x02, 0x02]; // Placeholder serialization
    Ok(Message {
        content_type: TASK_NAME.to_string(),
        wire_bytes,
        from: from.clone(),
        is_broadcast: true,
    })
}

// --- End Placeholder Crypto Operations/Types --- //

#[derive(Debug)]
pub struct Round2 {
    state: RoundState,
    out: Option<Sender<Message>>,
    end: Option<Sender<LocalPartySaveData>>,
    params: Arc<Parameters>,
    temp_data: Arc<Mutex<KeygenPartyTmpData>>,
    save_data: Arc<Mutex<KeyGenPartySaveData>>,
    started: bool,
    messages1_received: HashMap<PartyID, KGRound2Message1>,
    messages2_received: HashMap<PartyID, KGRound2Message2>,
}

impl Round2 {
    pub fn new(
        out_sender: Option<Sender<Message>>,
        end_sender: Option<Sender<LocalPartySaveData>>,
        params: Arc<Parameters>,
        save_data: Arc<Mutex<KeyGenPartySaveData>>,
        temp_data: Arc<Mutex<KeygenPartyTmpData>>,
    ) -> Result<Self, TssError> {
        Ok(Round2 {
            state: RoundState::new(2, params),
            out: out_sender,
            end: end_sender,
            params,
            temp_data,
            save_data,
            started: false,
            messages1_received: HashMap::new(),
            messages2_received: HashMap::new(),
        })
    }
}

impl Round for Round2 {
    fn round_number(&self) -> usize { self.state.round_number }
    fn state(&self) -> &RoundState { &self.state }
    fn state_mut(&mut self) -> &mut RoundState { &mut self.state }

    fn start(&mut self, ctx: &mut RoundCtx) -> Result<(), TssError> {
        if self.state.started {
            return Err(self.state.wrap_error("Round 2 already started".into(), None));
        }
        self.state.started = true;
        self.state.reset_ok();

        let party_id = ctx.params.party_id();
        let i = party_id.index;
        let mut rng = OsRng;

        // 6. Verify DLN proofs, store R1 message pieces, ensure uniqueness of h1j, h2j
        println!("Round 2: Verifying DLN proofs...");
        // TODO: Implement proper concurrency control if needed
        // let concurrency = std::thread::available_parallelism().map_or(1, |n| n.get());
        let dln_verifier = DlnProofVerifier::new(1); // Synchronous for now
        let mut h1h2_map: HashMap<String, PartyID> = HashMap::new();
        let mut dln_proof_results = vec![Ok(()); ctx.params.party_count() * 2]; // Store results or errors

        for (j, msg_opt) in ctx.temp.message_store.kg_round1_messages.iter().enumerate() {
            let msg = msg_opt.as_ref().ok_or_else(|| {
                self.state.wrap_error(format!("Missing Round 1 message from party {}", j).into(), None)
            })?;
            let r1_content = match &msg.content {
                 KeygenMessageEnum::Round1(c) => Ok(c),
                 _ => Err(self.state.wrap_error(format!("Expected Round1 message from party {}, got something else", j).into(), Some(&[msg.get_from()])))
            }?;

            let h1j = &r1_content.h1;
            let h2j = &r1_content.h2;
            let n_tilde_j = &r1_content.n_tilde;
            let paillier_pk_j = &r1_content.paillier_pk;

            // Basic checks from Go version
             if paillier_pk_j.n.bits() != PAILLIER_BITS_LEN as u64 { // Assuming n.bits() exists
                 return Err(self.state.wrap_error(format!("Party {} Paillier modulus has incorrect bit length", j).into(), Some(&[msg.get_from()])));
             }
             if h1j == h2j {
                 return Err(self.state.wrap_error(format!("Party {} h1j and h2j are equal", j).into(), Some(&[msg.get_from()])));
             }
             if n_tilde_j.bits() != PAILLIER_BITS_LEN as u64 { // Assuming n_tilde_j.bits() exists
                 return Err(self.state.wrap_error(format!("Party {} NTildej has incorrect bit length", j).into(), Some(&[msg.get_from()])));
             }

            // Check uniqueness of H1j, H2j
            let h1j_hex = h1j.to_str_radix(16);
            let h2j_hex = h2j.to_str_radix(16);
            if let Some(existing_party) = h1h2_map.get(&h1j_hex) {
                 return Err(self.state.wrap_error(format!("h1j from party {} already used by party {}", j, existing_party.index).into(), Some(&[msg.get_from(), existing_party])));
            }
             if let Some(existing_party) = h1h2_map.get(&h2j_hex) {
                 return Err(self.state.wrap_error(format!("h2j from party {} already used by party {}", j, existing_party.index).into(), Some(&[msg.get_from(), existing_party])));
            }
            h1h2_map.insert(h1j_hex, msg.get_from().clone());
            h1h2_map.insert(h2j_hex, msg.get_from().clone());

            // Verify DLN proofs (synchronous for now)
            if !dln_verifier.verify_dln_proof_1(r1_content, h1j, h2j, n_tilde_j) {
                dln_proof_results[j * 2] = Err(self.state.wrap_error(format!("DLNProof1 verification failed for party {}", j).into(), Some(&[msg.get_from()])));
            }
            if !dln_verifier.verify_dln_proof_2(r1_content, h2j, h1j, n_tilde_j) {
                 dln_proof_results[j * 2 + 1] = Err(self.state.wrap_error(format!("DLNProof2 verification failed for party {}", j).into(), Some(&[msg.get_from()])));
            }
        }

        // Check results
        for result in dln_proof_results {
            result?; // Propagate the first error encountered
        }
        println!("Round 2: DLN proofs verified.");

        // Save verified data from Round 1
        for (j, msg_opt) in ctx.temp.message_store.kg_round1_messages.iter().enumerate() {
            if j == i { continue; }
            let r1_content = match &msg_opt.as_ref().unwrap().content {
                KeygenMessageEnum::Round1(c) => c,
                _ => unreachable!(), // Should have failed earlier if not R1 message
            };
            // Save PaillierPK, NTilde, H1, H2, Commitment (KGC)
            ctx.data.paillier_pks[j] = Some(r1_content.paillier_pk.clone());
            ctx.data.n_tilde_j[j] = Some(r1_content.n_tilde.clone());
            ctx.data.h1j[j] = Some(r1_content.h1.clone());
            ctx.data.h2j[j] = Some(r1_content.h2.clone());
            ctx.temp.kgcs[j] = Some(r1_content.commitment.clone());
        }

        // 5. P2P send share ij to Pj + Factorization Proof
        let shares = ctx.temp.shares.as_ref().ok_or_else(|| self.state.wrap_error("Missing VSS shares".into(), None))?;
        let context_i = [get_ssid(ctx, &self.state)?.as_slice(), BigInt::from(i).to_bytes_be().1.as_slice()].concat();
        let paillier_sk = ctx.data.local_pre_params.paillier_sk.as_ref()
                           .ok_or_else(|| self.state.wrap_error("Missing Paillier SK".into(), None))?;
        let p_prime = &paillier_sk.p;
        let q_prime = &paillier_sk.q;

        for (j, pj) in self.state.parties.iter().enumerate() { // Use parties from RoundState
            let n_tilde_j = ctx.data.n_tilde_j[j].as_ref().ok_or_else(|| self.state.wrap_error(format!("Missing NTilde for party {}", j).into(), None))?;
            let h1j = ctx.data.h1j[j].as_ref().ok_or_else(|| self.state.wrap_error(format!("Missing H1 for party {}", j).into(), None))?;
            let h2j = ctx.data.h2j[j].as_ref().ok_or_else(|| self.state.wrap_error(format!("Missing H2 for party {}", j).into(), None))?;

            // TODO: Implement NoProofFac() check from parameters
            let curve_params = get_curve_params(CurveName::Ed25519)
                .ok_or_else(|| self.state.wrap_error("Ed25519 curve parameters not found".into(), None))?;
            let fac_proof = fac_proof::new(
                &context_i, &curve_params, &paillier_sk.public_key.n, n_tilde_j, h1j, h2j,
                p_prime, q_prime, &mut rng
            ).map_err(|e| self.state.wrap_error(e, Some(&[party_id])))?;

            let r2msg1 = new_kg_round2_message1(pj, party_id, &shares.0[j], fac_proof)
                           .map_err(|e| self.state.wrap_error(e, Some(&[party_id])))?;

             let parsed_msg = ParsedMessage { // Create ParsedMessage for storage
                 content: KeygenMessageEnum::Round2_1(r2msg1.content.clone()),
                 routing: MessageRouting { from: party_id.clone(), to: Some(vec![pj.clone()]), is_broadcast: false },
            };

            if j == i {
                // Store own message
                 self.store_message(ctx, parsed_msg)?; // Use the trait method for storing
            } else {
                // Send P2P message
                if let Some(sender) = self.out.as_ref() {
                     sender.send(r2msg1).map_err(|e| self.state.wrap_error(Box::new(e), Some(&[pj])))?;
                } else {
                     println!("Warning: Output channel is None in Round2::start (P2P)");
                }
            }
        }

        // 7. BROADCAST de-commitments of Shamir poly*G + Modulo Proof
        let decommitment = ctx.temp.de_commit_poly_g.as_ref()
                            .ok_or_else(|| self.state.wrap_error("Missing decommitment".into(), None))?;
        // TODO: Implement NoProofMod() check from parameters
         let mod_proof = mod_proof::new(&context_i, &paillier_sk.public_key.n, p_prime, q_prime, &mut rng)
                         .map_err(|e| self.state.wrap_error(e, Some(&[party_id])))?;

        let r2msg2 = new_kg_round2_message2(party_id, decommitment, mod_proof)
                        .map_err(|e| self.state.wrap_error(e, Some(&[party_id])))?;

         let parsed_msg = ParsedMessage { // Create ParsedMessage for storage
             content: KeygenMessageEnum::Round2_2(r2msg2.content.clone()),
             routing: MessageRouting { from: party_id.clone(), to: None, is_broadcast: true },
        };
        self.store_message(ctx, parsed_msg)?; // Store own message

        // Send broadcast message
         if let Some(sender) = self.out.as_ref() {
             sender.send(r2msg2).map_err(|e| self.state.wrap_error(Box::new(e), None))?;
         } else {
              println!("Warning: Output channel is None in Round2::start (Broadcast)");
         }

        Ok(())
    }

    fn can_accept(&self, msg: &ParsedMessage) -> bool {
        match msg.content() {
            KeygenMessageEnum::Round2_1(_) => !msg.is_broadcast(),
            KeygenMessageEnum::Round2_2(_) => msg.is_broadcast(),
            _ => false,
        }
    }

    fn update(&mut self, ctx: &RoundCtx) -> Result<bool, TssError> {
        let mut all_ok = true;
        for j in 0..ctx.params.party_count() {
            if self.state.ok[j] {
                continue;
            }
            // Check if both messages are received and valid types for party j
            let msg1_received = ctx.temp.message_store.kg_round2_message1s[j].as_ref()
                                 .map_or(false, |m| self.can_accept(m));
            let msg2_received = ctx.temp.message_store.kg_round2_message2s[j].as_ref()
                                 .map_or(false, |m| self.can_accept(m));

            if msg1_received && msg2_received {
                self.state.ok[j] = true;
            } else {
                all_ok = false; // Still waiting for one or both messages
            }
        }
        Ok(all_ok)
    }

     fn store_message(&mut self, ctx: &mut RoundCtx, msg: ParsedMessage) -> Result<(), TssError> {
         if !self.can_accept(&msg) {
             return Err(self.state.wrap_error("Cannot store unacceptable message in Round 2".into(), Some(&[msg.get_from()])));
         }
         let from_p_idx = msg.get_from().index;
          if from_p_idx >= ctx.params.party_count() {
               return Err(self.state.wrap_error(format!("Invalid party index {} in store_message", from_p_idx).into(), Some(&[msg.get_from()])));
          }

         match msg.content {
             KeygenMessageEnum::Round2_1(_) => {
                 ctx.temp.message_store.kg_round2_message1s[from_p_idx] = Some(msg);
             }
             KeygenMessageEnum::Round2_2(_) => {
                 ctx.temp.message_store.kg_round2_message2s[from_p_idx] = Some(msg);
             }
             _ => return Err(self.state.wrap_error("Invalid message type passed to Round 2 store_message".into(), Some(&[msg.get_from()]))),
         }
         Ok(())
    }

    fn next_round(self: Box<Self>) -> Result<Option<Box<dyn Round>>, TssError> {
         // Reset started state? Go version does this.
         // self.state_mut().started = false;
         Ok(Some(Box::new(Round3::new(self.out, self.end, self.state.parties.as_ref())?))) // Pass necessary context/state
    }

    // --- Context Accessor Methods --- //
    fn params(&self) -> &Parameters { unimplemented!("Accessor needs context") }
    fn data(&self) -> &LocalPartySaveData { unimplemented!("Accessor needs context") }
    fn data_mut(&mut self) -> &mut LocalPartySaveData { unimplemented!("Accessor needs context") }
    fn temp(&self) -> &LocalTempData { unimplemented!("Accessor needs context") }
    fn temp_mut(&mut self) -> &mut LocalTempData { unimplemented!("Accessor needs context") }
    fn out_channel(&self) -> &Option<Sender<Message>> { &self.out }
    fn end_channel(&self) -> &Option<Sender<LocalPartySaveData>> { &self.end }
}
