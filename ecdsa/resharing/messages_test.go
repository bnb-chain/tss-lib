// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/v4/crypto/modproof"
	. "github.com/bnb-chain/tss-lib/v4/ecdsa/resharing"
)

// nonEmptyParts builds a [][]byte of n non-empty parts, which is exactly the
// shape common.NonEmptyMultiBytes(bzs, n) accepts and exactly what
// modproof.NewProofFromBytes / dlnproof.UnmarshalDLNProof require.
func nonEmptyParts(n int) [][]byte {
	parts := make([][]byte, n)
	for i := range parts {
		parts[i] = []byte{0x01}
	}
	return parts
}

// wellFormed2048 returns a 2048-bit modulus-shaped byte slice, satisfying the
// bit-length floor DGRound2Message1.ValidateBasic enforces.
func wellFormed2048() []byte {
	return new(big.Int).Lsh(big.NewInt(1), 2047).Bytes()
}

// wellFormedDGRound2Message1 is the positive control: every field carries the
// shape an honest sender emits (see NewDGRound2Message1 /
// round_2_new_step_1.go). ValidateBasic is purely structural, so synthetic
// byte parts of the right arity are indistinguishable from real proofs here.
func wellFormedDGRound2Message1() *DGRound2Message1 {
	return &DGRound2Message1{
		PaillierN:      wellFormed2048(),
		ModProof:       nonEmptyParts(modproof.ProofModBytesParts),
		NTilde:         wellFormed2048(),
		H1:             []byte{0x02},
		H2:             []byte{0x03},
		Dlnproof_1:     nonEmptyParts(2 + dlnproof.Iterations*2),
		Dlnproof_2:     nonEmptyParts(2 + dlnproof.Iterations*2),
		NTildeModProof: nonEmptyParts(modproof.ProofModBytesParts),
	}
}

// TestDGRound2Message1ValidateBasicRequiresNTildeModProof pins the message
// layer to what protob/ecdsa-resharing.proto already declares and what round 4
// already enforces: nTildeModProof is NOT optional. A message whose
// nTildeModProof is absent, short, or carries an empty part cannot be turned
// into a ProofMod by modproof.NewProofFromBytes, so round_4_new_step_2.go
// marks the sender a culprit and aborts the round. Rejecting it here changes
// only WHERE that rejection happens, never WHETHER it happens.
func TestDGRound2Message1ValidateBasicRequiresNTildeModProof(t *testing.T) {
	// Negative control: the honest shape must still be accepted.
	assert.True(t, wellFormedDGRound2Message1().ValidateBasic(),
		"a well-formed message must still pass ValidateBasic")

	t.Run("absent", func(t *testing.T) {
		m := wellFormedDGRound2Message1()
		m.NTildeModProof = nil
		assert.False(t, m.ValidateBasic())
	})

	t.Run("empty slice", func(t *testing.T) {
		m := wellFormedDGRound2Message1()
		m.NTildeModProof = [][]byte{}
		assert.False(t, m.ValidateBasic())
	})

	t.Run("too few parts", func(t *testing.T) {
		m := wellFormedDGRound2Message1()
		m.NTildeModProof = nonEmptyParts(modproof.ProofModBytesParts - 1)
		assert.False(t, m.ValidateBasic())
	})

	t.Run("too many parts", func(t *testing.T) {
		m := wellFormedDGRound2Message1()
		m.NTildeModProof = nonEmptyParts(modproof.ProofModBytesParts + 1)
		assert.False(t, m.ValidateBasic())
	})

	t.Run("one empty part", func(t *testing.T) {
		m := wellFormedDGRound2Message1()
		m.NTildeModProof = nonEmptyParts(modproof.ProofModBytesParts)
		m.NTildeModProof[7] = nil
		assert.False(t, m.ValidateBasic())
	})
}

// TestDGRound2Message1ValidateBasicAcceptsWhatUnmarshalAccepts is the
// no-false-positive guarantee behind the check above: ValidateBasic must
// accept a nTildeModProof exactly when UnmarshalNTildeModProof can decode it.
// If the two ever disagreed, ValidateBasic would be rejecting a proof the
// round would have been happy with.
func TestDGRound2Message1ValidateBasicAcceptsWhatUnmarshalAccepts(t *testing.T) {
	for _, n := range []int{
		0,
		1,
		modproof.ProofModBytesParts - 1,
		modproof.ProofModBytesParts,
		modproof.ProofModBytesParts + 1,
	} {
		m := wellFormedDGRound2Message1()
		m.NTildeModProof = nonEmptyParts(n)
		_, err := m.UnmarshalNTildeModProof()
		assert.Equal(t, err == nil, m.ValidateBasic(),
			"ValidateBasic and UnmarshalNTildeModProof must agree for %d parts", n)
	}
}
