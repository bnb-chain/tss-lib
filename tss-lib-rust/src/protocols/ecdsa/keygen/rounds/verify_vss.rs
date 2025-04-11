// src/protocols/ecdsa/keygen/rounds/verify_vss.rs

use crate::{
    crypto::{
        commitments::hash::HashCommitment,
        ecpoint::ECPoint,
        facproof::ProofFac,
        modproof::ProofMod,
        vss::Share as VssShare,
    },
    tss::{
        curve::Curve,
        party_id::PartyID,
        error::{RoundError, RoundErr},
        params::Parameters, // Needed for curve and threshold
    },
    crypto::paillier::PublicKey as PaillierPk,
};
use std::sync::{
    mpsc::{channel, Sender, Receiver},
    Arc,
};
use threadpool::ThreadPool;
use num_bigint_dig::BigInt;
use anyhow::Result;
use log::{debug, error};

/// Context for verifying one party's VSS share and related proofs.
#[derive(Clone)] // Needed for moving into threads
pub struct VssVerifyContext {
    pub party_index: usize,
    pub commitment_c_j: Vec<u8>,
    pub decommitment_d_j: (Vec<[u8; 32]>, Vec<u8>),
    pub mod_proof: ProofMod,
    pub fac_proof: ProofFac,
    pub received_vss_share_ij: VssShare,
    pub paillier_pk_j: PaillierPk,
    pub n_tilde_j: BigInt,
    pub h1_j: BigInt,
    pub h2_j: BigInt,
    pub context_j: Vec<u8>, // SSID || j
    pub no_proof_mod: bool,
    pub no_proof_fac: bool,
}

/// Result of verifying one party's VSS share and proofs.
pub struct VssVerificationResult {
    pub party_index: usize,
    pub vss_points: Option<Vec<ECPoint<Curve>>>, // Decommitted VSS points if valid
    pub error_reason: Option<String>, // Reason for failure
}

impl VssVerificationResult {
    pub fn is_valid(&self) -> bool {
        self.error_reason.is_none() && self.vss_points.is_some()
    }
}

/// Manages concurrent verification of VSS shares and proofs.
pub struct VssVerifier {
    pool: ThreadPool,
    sender: Sender<VssVerificationResult>,
    receiver: Receiver<VssVerificationResult>,
}

impl VssVerifier {
    pub fn new(concurrency: usize) -> Self {
        let (sender, receiver) = channel();
        let pool = ThreadPool::new(concurrency);
        Self { pool, sender, receiver }
    }

    /// Queues a verification task for a single party's VSS share and proofs.
    pub fn verify_vss_share_and_proofs(
        &self,
        context: VssVerifyContext,
        curve: Curve, // Pass curve explicitly
        threshold: usize,
        verifier_party_id: PartyID, // ID of the party *doing* the verification
    ) {
        let sender_clone = self.sender.clone();

        self.pool.execute(move || {
            let party_idx = context.party_index;
            debug!(target: "tss-lib", verifier_id = ?verifier_party_id, target_party_idx = party_idx, "Verifying VSS/Proofs in background");

            let mut error_reason: Option<String> = None;
            let mut vss_points_result: Option<Vec<ECPoint<Curve>>> = None;

            // 1. Decommit VSS Commitment C_j
            let hash_commit_decommit = HashCommitment::new(context.commitment_c_j, context.decommitment_d_j);
            match hash_commit_decommit.decommit() {
                Ok(points) => vss_points_result = Some(points),
                Err(e) => {
                     error_reason = Some(format!("VSS decommitment failed: {}", e));
                }
            }

            // Proceed only if decommitment succeeded
            if error_reason.is_none() {
                 let vss_points = vss_points_result.as_ref().unwrap(); // Safe unwrap

                 // 2. Verify ModProof (N_j)
                 if !context.no_proof_mod {
                     if !context.mod_proof.verify(&context.context_j, &context.paillier_pk_j.n) {
                         error_reason = Some("ModProof verification failed".to_string());
                     }
                 } else {
                     debug!(target: "tss-lib", verifier_id = ?verifier_party_id, target_party_idx = party_idx, "Skipped ModProof verification");
                 }

                 // 3. Verify VSS Share (using V_cj)
                 if error_reason.is_none() && !context.received_vss_share_ij.verify(curve, threshold, vss_points) {
                     error_reason = Some("VSS share verification failed".to_string());
                 }

                 // 4. Verify FacProof (N_j, N^_i)
                 if error_reason.is_none() && !context.no_proof_fac {
                     if !context.fac_proof.verify(
                         &context.context_j,
                         &curve.order(),
                         &context.paillier_pk_j.n,
                         &context.n_tilde_j,
                         &context.h1_j,
                         &context.h2_j,
                     ) {
                         error_reason = Some("FacProof verification failed".to_string());
                     }
                 } else if error_reason.is_none() {
                      debug!(target: "tss-lib", verifier_id = ?verifier_party_id, target_party_idx = party_idx, "Skipped FacProof verification");
                 }
            }

            let result = VssVerificationResult {
                party_index: party_idx,
                vss_points: if error_reason.is_none() { vss_points_result } else { None }, // Only return points if all checks passed
                error_reason,
            };

            if let Err(e) = sender_clone.send(result) {
                log::error!("Failed to send VSS verification result for party {}: {}", party_idx, e);
            }
        });
    }

     /// Collects all verification results.
    pub fn collect_results(&self, expected_count: usize) -> Vec<VssVerificationResult> {
         debug!(target: "tss-lib", expected_results=expected_count, "Collecting VSS verification results...");
        self.pool.join(); // Wait for all threads
         debug!(target: "tss-lib", "VSS verification threads joined.");
        self.receiver.try_iter().collect()
    }
}

/// Helper function to verify VSS shares and proofs for multiple parties concurrently.
pub fn verify_vss_share_and_proofs(
    contexts: Vec<VssVerifyContext>,
    curve: Curve,
    threshold: usize,
    verifier_party_id: PartyID,
    concurrency: usize,
) -> Result<Vec<VssVerificationResult>> {
    let verifier = VssVerifier::new(concurrency);
    let expected_count = contexts.len();
    for context in contexts {
        verifier.verify_vss_share_and_proofs(context, curve, threshold, verifier_party_id.clone());
    }
    let results = verifier.collect_results(expected_count);
     if results.len() != expected_count {
          log::error!(
             target: "tss-lib",
             expected = expected_count,
             actual = results.len(),
             "VSS verification result count mismatch!"
         );
         return Err(anyhow::anyhow!("VSS verification result count mismatch: expected {}, got {}", expected_count, results.len()));
     }
    Ok(results)
} 