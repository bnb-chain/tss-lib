// Copyright © 2026 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/tss"
)

// TestNewParametersRejectsModQDuplicateIDs verifies the dedup-mod-q
// invariant: two PartyIDs whose Keys differ by exactly the curve order q
// have raw-byte-distinct Keys (passing SortPartyIDs) but the same Lagrange
// x-coordinate, which previously caused a `ModInverse(0, q)` panic deep
// inside signing/prepare.go. NewParameters must reject this configuration
// up-front.
func TestNewParametersRejectsModQDuplicateIDs(t *testing.T) {
	ec := tss.S256()
	q := ec.Params().N
	k := big.NewInt(42)
	kPlusQ := new(big.Int).Add(k, q)
	p1 := tss.NewPartyID("1", "P1", k)
	p2 := tss.NewPartyID("2", "P2", kPlusQ)
	sorted := tss.SortPartyIDs(tss.UnSortedPartyIDs{p1, p2})
	ctx := tss.NewPeerContext(sorted)

	defer func() {
		r := recover()
		assert.NotNil(t, r, "NewParameters must panic on mod-q collision")
		err, ok := r.(error)
		assert.True(t, ok)
		assert.Contains(t, err.Error(), "collide mod q")
	}()
	tss.NewParameters(ec, ctx, p1, 2, 1)
}

// TestNewParametersAcceptsHonestIDs sanity-checks that the new check does
// not regress honest configurations (k and k+1 differ by 1, not q).
func TestNewParametersAcceptsHonestIDs(t *testing.T) {
	ec := tss.S256()
	p1 := tss.NewPartyID("1", "P1", big.NewInt(42))
	p2 := tss.NewPartyID("2", "P2", big.NewInt(43))
	sorted := tss.SortPartyIDs(tss.UnSortedPartyIDs{p1, p2})
	ctx := tss.NewPeerContext(sorted)
	assert.NotNil(t, tss.NewParameters(ec, ctx, p1, 2, 1))
}

// TestNewParametersRejectsZeroResidueID verifies that a PartyID whose
// `KeyInt() mod q == 0` (e.g. Key set to q itself, or any non-zero
// multiple of q) is rejected up-front. A zero residue would, post-
// Lagrange, either give that party the raw Shamir secret as their
// share or collapse peer `bigWj.ScalarMult(iota=0)` to nil at signing
// time in ecdsa/signing/prepare.go.
func TestNewParametersRejectsZeroResidueID(t *testing.T) {
	ec := tss.S256()
	q := ec.Params().N
	p1 := tss.NewPartyID("1", "P1", big.NewInt(42))
	pZero := tss.NewPartyID("0", "P0", q) // Key == q, so mod q == 0
	sorted := tss.SortPartyIDs(tss.UnSortedPartyIDs{p1, pZero})
	ctx := tss.NewPeerContext(sorted)

	defer func() {
		r := recover()
		assert.NotNil(t, r, "NewParameters must panic on zero-residue PartyID")
		err, ok := r.(error)
		assert.True(t, ok)
		assert.Contains(t, err.Error(), "congruent to 0 mod q")
	}()
	tss.NewParameters(ec, ctx, p1, 2, 1)
}
