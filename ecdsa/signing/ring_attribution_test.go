// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// Every proof in crypto/mta is built under the COUNTERPARTY's ring and verified
// by that same counterparty. So a ring that makes a correctly computed proof
// unacceptable produces a complaint, and the question these tests pin is who the
// complaint names. It must be the party that supplied the ring, never the party
// that merely computed the proof into it.
//
// The ring is corrupted in a way the shape gate rejects outright (h1 == h2,
// which both mta verifiers reject) so that the routing is exercised
// deterministically. crypto/mta covers the case that only shows up some of the
// time, where the ring passes every gate and the computed value lands on one
// the verifier rejects.
func TestRoundOneNamesTheSupplierOfAnUnusableRing(t *testing.T) {
	setUp("info")

	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	assert.NoError(t, err, "should load keygen fixtures")
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(signPIDs), signPIDs[0], len(signPIDs), testThreshold)
	params.SetSessionNonce(big.NewInt(1))

	// Peer at index 1 is the one whose ring is unusable.
	const culpritIdx = 1
	key := keys[0]
	key.H2j = append([]*big.Int(nil), key.H2j...)
	key.H2j[culpritIdx] = key.H1j[culpritIdx]

	outCh := make(chan tss.Message, 16)
	endCh := make(chan *common.SignatureData, 1)
	P := NewLocalParty(big.NewInt(42), params, key, outCh, endCh).(*LocalParty)

	tssErr := P.Start()
	if !assert.NotNil(t, tssErr, "round 1 must refuse to prove into a ring its verifier would reject") {
		return
	}
	culprits := tssErr.Culprits()
	if !assert.Len(t, culprits, 1, "exactly the ring's supplier must be named, got %v", culprits) {
		return
	}
	assert.Equal(t, signPIDs[culpritIdx].Id, culprits[0].Id,
		"the party that supplied the ring must be named, not the party that proved into it")
	assert.NotEqual(t, P.PartyID().Id, culprits[0].Id,
		"the local party must never be named for its counterparty's parameters")
	assert.Equal(t, 0, len(outCh), "nothing may go out once the round has refused")
}

// Negative control. Naming a culprit for every failure, or failing always, would
// satisfy the test above just as well: with the fixtures untouched, round 1 must
// simply run.
func TestRoundOneRunsWithTheFixtureRings(t *testing.T) {
	setUp("info")

	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	assert.NoError(t, err, "should load keygen fixtures")
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(signPIDs), signPIDs[0], len(signPIDs), testThreshold)
	params.SetSessionNonce(big.NewInt(1))

	outCh := make(chan tss.Message, 16)
	endCh := make(chan *common.SignatureData, 1)
	P := NewLocalParty(big.NewInt(42), params, keys[0], outCh, endCh).(*LocalParty)

	assert.Nil(t, P.Start(), "an ordinary committee must not be refused")
	assert.Equal(t, testThreshold+1, len(outCh), "round 1 emits N-1 P2P messages and one broadcast")
}
