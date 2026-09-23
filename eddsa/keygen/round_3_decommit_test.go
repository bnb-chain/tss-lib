// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	cmts "github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// TestRound3RejectsEmptyDecommitment is the regression test for SRC-2026-925.
//
// A malicious EdDSA keygen participant commits in round 1 to only its
// randomness `r` (C = SHA512_256i(r), no polynomial points) and broadcasts a
// round-2 decommitment of one element `[r]`. Before the fix, that decommitment
// passed the round-3 guard `!ok || flatPolyGs == nil` (DeCommit returns an
// empty *non-nil* slice), UnFlattenECPoints returned a zero-length slice, and
// `proof.Verify(ContextJ, PjVs[0])` indexed element 0 of an empty slice,
// panicking ("index out of range [0] with length 0") inside the un-recover()'d
// keygen goroutine — an unattributable, repeatable process crash.
//
// The fix (round_3.go) adds a length check; the malicious peer must now be
// rejected with a normal *tss.Error (attributed to the sender), not a panic.
func TestRound3RejectsEmptyDecommitment(t *testing.T) {
	ec := edwards.Edwards()
	q := ec.Params().N

	// 2-of-2 committee; party 0 is the honest victim, party 1 the attacker.
	pIDs := tss.GenerateTestPartyIDs(2)
	p2pCtx := tss.NewPeerContext(pIDs)
	params := tss.NewParameters(ec, p2pCtx, pIDs[0], len(pIDs), 1)

	ids := []*big.Int{pIDs[0].KeyInt(), pIDs[1].KeyInt()}

	// Victim's own honest VSS + Schnorr proof (so round 3's pre-amble succeeds).
	ui := common.GetRandomPositiveInt(rand.Reader, q)
	vs, shares, err := vss.Create(ec, params.Threshold(), ui, ids, rand.Reader)
	assert.NoError(t, err)
	pii, err := schnorr.NewZKProof([]byte("ssid"), ui, vs[0], rand.Reader)
	assert.NoError(t, err)

	// Malicious party 1: commit to ONLY the randomness r, then decommit [r].
	r := common.MustGetRandomInt(rand.Reader, 256)
	evilCmt := cmts.NewHashCommitmentWithRandomness(r) // C = H(r), D = [r]
	assert.Equal(t, 1, len(evilCmt.D), "attacker decommitment must be a single element [r]")

	// Hand-build the victim's round 3 with a populated temp.
	save := NewLocalPartySaveData(len(pIDs))
	temp := localTempData{}
	temp.ssid = []byte("ssid")
	temp.ui = ui
	temp.vs = vs
	temp.shares = shares
	temp.KGCs = make([]cmts.HashCommitment, len(pIDs))
	temp.kgRound2Message1s = make([]tss.ParsedMessage, len(pIDs))
	temp.kgRound2Message2s = make([]tss.ParsedMessage, len(pIDs))

	// Attacker's commitment slot and the two round-2 messages it "sent".
	temp.KGCs[1] = evilCmt.C
	temp.kgRound2Message1s[1] = NewKGRound2Message1(pIDs[0], pIDs[1], shares[1])
	temp.kgRound2Message2s[1] = NewKGRound2Message2(pIDs[1], evilCmt.D, pii)

	out := make(chan tss.Message, len(pIDs))
	end := make(chan *LocalPartySaveData, 1)
	b := &base{
		Parameters: params,
		save:       &save,
		temp:       &temp,
		out:        out,
		end:        end,
		ok:         make([]bool, len(pIDs)),
	}
	round := &round3{&round2{&round1{b}}}

	// Must NOT panic, and must reject the attacker with an attributed error.
	var tssErr *tss.Error
	assert.NotPanics(t, func() {
		tssErr = round.Start()
	}, "SRC-2026-925: empty decommitment must not panic the keygen goroutine")

	assert.NotNil(t, tssErr, "round 3 must reject the single-element decommitment")
	if tssErr != nil {
		culprits := tssErr.Culprits()
		assert.Len(t, culprits, 1)
		if len(culprits) == 1 {
			assert.Equal(t, pIDs[1].Id, culprits[0].Id, "the malicious sender must be attributed as the culprit")
		}
	}
}

// TestShortDecommitmentUnFlattenIsNonNil locks in the primitive facts the
// SRC-2026-925 guard relies on.
//
// Two layers stand between a wrong-length decommitment and the panic that
// SRC-2026-925 was about, and this test pins both:
//
//  1. The primitive itself now refuses fewer than two parts, so the degenerate
//     [r] case -- a commitment carrying no secret at all -- never opens. That
//     bound was added after this test was first written; before it, [r]
//     verified and DeCommit handed back an empty slice.
//  2. The bound does NOT make the round-3 length check redundant. Any
//     decommitment with two or more parts still opens, and unflattening a
//     short-but-legal one yields a zero-... non-nil slice of the wrong length.
//     `flatPolyGs == nil` alone therefore still does not reject it, which is
//     why round 3 checks the count explicitly.
func TestShortDecommitmentUnFlattenIsNonNil(t *testing.T) {
	r := common.MustGetRandomInt(rand.Reader, 256)

	// Layer 1: a commitment carrying no secret does not open at all.
	degenerate := cmts.NewHashCommitmentWithRandomness(r)
	ok, flat := degenerate.DeCommit()
	assert.False(t, ok, "a decommitment of fewer than two parts must not open")
	assert.Nil(t, flat, "and it must hand back nothing")

	// Layer 2: a two-part decommitment DOES open, and its unflattened form is
	// non-nil with the wrong length -- the case the round-3 count check exists
	// for. (threshold+1)*2 coordinates are expected for any real VSS
	// commitment; one coordinate is not that.
	short := cmts.NewHashCommitmentWithRandomness(r, big.NewInt(7))
	ok, flat = short.DeCommit()
	assert.True(t, ok, "a two-part commitment verifies")
	assert.NotNil(t, flat, "DeCommit returns a non-nil slice")
	assert.Len(t, flat, 1, "carrying exactly the one committed value")

	const expectedForThreshold1 = (1 + 1) * 2
	assert.NotEqual(t, expectedForThreshold1, len(flat),
		"so only an explicit count check rejects it")
}
