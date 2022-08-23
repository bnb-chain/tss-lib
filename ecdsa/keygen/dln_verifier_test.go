// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/crypto/dlnproof"
)

func BenchmarkDLNProofVerification(b *testing.B) {
	localPartySaveData, _, err := LoadKeygenTestFixtures(1)
	if err != nil {
		b.Fatal(err)
	}

	params := localPartySaveData[0].LocalPreParams

	proof := dlnproof.NewDLNProof(
		params.H1i,
		params.H2i,
		params.Alpha,
		params.P,
		params.Q,
		params.NTildei,
	)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		proof.Verify(params.H1i, params.H2i, params.NTildei)
	}
}

func TestVerifyDLNProof1_Success(t *testing.T) {
	preParams, proof := prepareProof(t)
	message := &KGRound1Message{
		Dlnproof_1: proof,
	}

	verifier := NewDlnProofVerifier()

	resultChan := make(chan bool)

	verifier.VerifyDLNProof1(message, preParams.H1i, preParams.H2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if !success {
		t.Fatal("expected positive verification")
	}
}

func TestVerifyDLNProof1_MalformedMessage(t *testing.T) {
	preParams, proof := prepareProof(t)
	message := &KGRound1Message{
		Dlnproof_1: proof[:len(proof)-1], // truncate
	}

	verifier := NewDlnProofVerifier()

	resultChan := make(chan bool)

	verifier.VerifyDLNProof1(message, preParams.H1i, preParams.H2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyDLNProof1_IncorrectProof(t *testing.T) {
	preParams, proof := prepareProof(t)
	message := &KGRound1Message{
		Dlnproof_1: proof,
	}

	verifier := NewDlnProofVerifier()

	resultChan := make(chan bool)

	wrongH1i := preParams.H1i.Sub(preParams.H1i, big.NewInt(1))
	verifier.VerifyDLNProof1(message, wrongH1i, preParams.H2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyDLNProof2_Success(t *testing.T) {
	preParams, proof := prepareProof(t)
	message := &KGRound1Message{
		Dlnproof_2: proof,
	}

	verifier := NewDlnProofVerifier()

	resultChan := make(chan bool)

	verifier.VerifyDLNProof2(message, preParams.H1i, preParams.H2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if !success {
		t.Fatal("expected positive verification")
	}
}

func TestVerifyDLNProof2_MalformedMessage(t *testing.T) {
	preParams, proof := prepareProof(t)
	message := &KGRound1Message{
		Dlnproof_2: proof[:len(proof)-1], // truncate
	}

	verifier := NewDlnProofVerifier()

	resultChan := make(chan bool)

	verifier.VerifyDLNProof2(message, preParams.H1i, preParams.H2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyDLNProof2_IncorrectProof(t *testing.T) {
	preParams, proof := prepareProof(t)
	message := &KGRound1Message{
		Dlnproof_2: proof,
	}

	verifier := NewDlnProofVerifier()

	resultChan := make(chan bool)

	wrongH2i := preParams.H2i.Add(preParams.H2i, big.NewInt(1))
	verifier.VerifyDLNProof2(message, preParams.H1i, wrongH2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

// TestOptionalConcurrency check that if the concurrency level optional flag
// is set, it is taken into account.
func TestOptionalConcurrency(t *testing.T) {
	concurrency := 7161

	verifier := NewDlnProofVerifier(concurrency)

	if cap(verifier.semaphore) != concurrency {
		t.Fatal("unexpected concurrency level")
	}
}

func prepareProof(t *testing.T) (*LocalPreParams, [][]byte) {
	localPartySaveData, _, err := LoadKeygenTestFixtures(1)
	if err != nil {
		t.Fatal(err)
	}

	preParams := localPartySaveData[0].LocalPreParams

	proof := dlnproof.NewDLNProof(
		preParams.H1i,
		preParams.H2i,
		preParams.Alpha,
		preParams.P,
		preParams.Q,
		preParams.NTildei,
	)

	serialized, err := proof.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	return &preParams, serialized
}
