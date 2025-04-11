// src/protocols/ecdsa/keygen/rounds/dln_proof_verifier.rs

// Helper struct and functions for verifying DLN proofs concurrently.
// This mirrors the approach in the Go code but adapted for Rust's concurrency model.

use crate::{
    crypto::dlnproof::Proof as DlnProof,
    protocols::ecdsa::keygen::messages::KGRound1Message,
    tss::party_id::PartyID,
};
use num_bigint_dig::BigInt;
use std::sync::{
    mpsc::{channel, Sender, Receiver},
    Arc,
};
use threadpool::ThreadPool; // Using threadpool crate for managing concurrency
use anyhow::Result;
use log::debug;

/// Context needed to verify a single party's DLN proofs.
#[derive(Clone)] // Clone needed for moving into threads
pub struct DlnProofVerifierContext {
    pub r1_msg: KGRound1Message, // Contains both proofs
    pub from_party_id: PartyID,
}

impl DlnProofVerifierContext {
    pub fn new(r1_msg: KGRound1Message, from_party_id: PartyID) -> Self {
        Self { r1_msg, from_party_id }
    }
}

/// Result of verifying one party's DLN proofs.
pub struct DlnProofVerificationResult {
    pub proof1_valid: bool,
    pub proof2_valid: bool,
    pub culprit: PartyID, // The party whose proofs were checked
}

/// Manages concurrent verification of DLN proofs.
pub struct DlnProofVerifier {
    pool: ThreadPool,
    sender: Sender<DlnProofVerificationResult>,
    receiver: Receiver<DlnProofVerificationResult>,
}

impl DlnProofVerifier {
    /// Creates a new verifier with a specified concurrency level.
    pub fn new(concurrency: usize) -> Self {
        let (sender, receiver) = channel();
        let pool = ThreadPool::new(concurrency);
        Self { pool, sender, receiver }
    }

    /// Queues a DLN proof pair verification task.
    pub fn verify_dln_proofs(&self, context: DlnProofVerifierContext) {
        let sender_clone = self.sender.clone();

        self.pool.execute(move || {
             debug!(target: "tss-lib", party_id = ?context.from_party_id, "Verifying DLN proofs in background thread");

            // Extract data from context
            let proof1 = &context.r1_msg.dln_proof1;
            let proof2 = &context.r1_msg.dln_proof2;
            let h1 = &context.r1_msg.h1;
            let h2 = &context.r1_msg.h2;
            let ntilde = &context.r1_msg.ntilde;

            // Verify Proof 1 (h2 = h1^alpha mod ntilde)
            let proof1_valid = proof1.verify(h1, h2, ntilde);

            // Verify Proof 2 (h1 = h2^beta mod ntilde)
            let proof2_valid = proof2.verify(h2, h1, ntilde);

            let result = DlnProofVerificationResult {
                proof1_valid,
                proof2_valid,
                culprit: context.from_party_id,
            };

            if let Err(e) = sender_clone.send(result) {
                 log::error!("Failed to send DLN verification result: {}", e);
            }
        });
    }

    /// Collects all verification results.
    /// Blocks until all queued tasks are completed.
    pub fn collect_results(&self, expected_count: usize) -> Vec<DlnProofVerificationResult> {
         debug!(target: "tss-lib", expected_results=expected_count, "Collecting DLN verification results...");
        self.pool.join(); // Wait for all threads to finish
         debug!(target: "tss-lib", "DLN verification threads joined.");

        // Collect results non-blockingly after join
        self.receiver.try_iter().collect()
        // Note: If the count doesn't match, something went wrong (e.g., send error)
        // Consider adding error handling or count checks here.
        // For simplicity, we assume all sends succeeded if pool.join() completes.
    }
}

/// Helper function to verify proofs for multiple parties concurrently.
pub fn verify_dln_proofs(
    contexts: &[DlnProofVerifierContext],
    concurrency: usize,
) -> Result<Vec<DlnProofVerificationResult>> {
    let verifier = DlnProofVerifier::new(concurrency);
    for context in contexts {
        verifier.verify_dln_proofs(context.clone());
    }
    // Collect results - important to get the correct expected count
    let results = verifier.collect_results(contexts.len());
    if results.len() != contexts.len() {
         // Log the discrepancy for debugging
         log::error!(
             target: "tss-lib",
             expected = contexts.len(),
             actual = results.len(),
             "DLN verification result count mismatch!"
         );
         // Depending on requirements, might return error or proceed with partial results
         // For now, let's return an error to indicate failure.
         return Err(anyhow::anyhow!("DLN verification result count mismatch: expected {}, got {}", contexts.len(), results.len()));
    }
    Ok(results)
} 