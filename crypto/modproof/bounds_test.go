// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package modproof_test

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	. "github.com/bnb-chain/tss-lib/v4/crypto/modproof"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
)

// W arrives from the wire with nothing bounding its size: NewProofFromBytes
// counts the parts and never measures one, and KGRound2Message2.ValidateBasic
// does not look at the proof at all. big.Jacobi reduces its argument modulo N
// first, so its cost grows with the size of W while Sign/Cmp does not. A W
// outside (0, N) must therefore be refused by the comparisons, not after a
// residuosity test it was never going to survive.
//
// What is asserted is that the REJECTION COST DOES NOT DEPEND ON W's SIZE,
// measured inside one tree by comparing a tiny out-of-range W against a large
// one. An absolute threshold cannot express this: at a megabit W the difference
// is 0.6 ms against 40 ns, which any threshold loose enough to be stable also
// swallows. This form goes red on the pre-reordering code and green after it.
func TestRejectingAnOutOfRangeWDoesNotDependOnItsSize(t *testing.T) {
	N := new(big.Int).Mul(
		common.GetRandomPrimeInt(rand.Reader, 1024),
		common.GetRandomPrimeInt(rand.Reader, 1024),
	)
	build := func(W *big.Int) *ProofMod {
		pf := &ProofMod{W: W}
		for i := range pf.X {
			pf.X[i] = big.NewInt(1)
		}
		for i := range pf.Z {
			pf.Z[i] = big.NewInt(1)
		}
		pf.A, pf.B = big.NewInt(1), big.NewInt(1)
		return pf
	}
	timeRejection := func(W *big.Int) time.Duration {
		pf := build(W)
		best := time.Duration(1<<62 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			assert.False(t, pf.Verify(Session, N), "a W outside (0, N) must be rejected")
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}

	// Both are out of range. Only their size differs: N is one above the
	// interval's top, the other is 8 MB of it.
	small := timeRejection(new(big.Int).Set(N))
	huge := timeRejection(new(big.Int).Lsh(big.NewInt(1), 1<<26))

	t.Logf("rejection of an out-of-range W: tiny=%s huge=%s", small, huge)
	assert.Less(t, huge, 4*small,
		"the cost of rejecting an out-of-range W must not scale with the operand "+
			"(tiny=%s, huge=%s); it does when residuosity is tested before the range",
		small, huge)
}

// Negative control for the reordering: the accept set is unchanged, so an
// honest proof must still verify and a W that is in range but a quadratic
// residue must still be rejected -- by the check that now runs last.
func TestVerifyStillDecidesInRangeProofs(t *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(t, err)
	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N

	pf, err := NewProof(Session, N, P, Q, rand.Reader)
	assert.NoError(t, err)
	assert.True(t, pf.Verify(Session, N), "an honest proof must still verify")

	// W is required to be a quadratic NON-residue; a square is in range and must
	// still be refused, which is exactly the check that moved.
	tampered := *pf
	tampered.W = new(big.Int).Exp(big.NewInt(7), big.NewInt(2), N)
	assert.False(t, tampered.Verify(Session, N),
		"an in-range quadratic residue must still be rejected")
}
