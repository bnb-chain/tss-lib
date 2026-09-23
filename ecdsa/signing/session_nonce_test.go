// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// newNonceTestParty builds a single signing party over the deterministic
// fixture set. The fixtures are loaded in order rather than at random because
// the committee decides every input to getSSID, and the SSID is what these
// tests compare.
func newNonceTestParty(t *testing.T, m, nonce *big.Int) (*LocalParty, chan tss.Message) {
	t.Helper()
	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	assert.NoError(t, err, "should load keygen fixtures")
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(signPIDs), signPIDs[0], len(signPIDs), testThreshold)
	if nonce != nil {
		params.SetSessionNonce(nonce)
	}
	outCh := make(chan tss.Message, 16)
	endCh := make(chan *common.SignatureData, 1)
	return NewLocalParty(m, params, keys[0], outCh, endCh).(*LocalParty), outCh
}

// TestRound1RequiresSessionNonce pins the fail-closed contract: a caller that
// has not agreed a session nonce with its peers gets an error out of round 1
// and nothing on the wire. There is no fallback value; one the library picks
// for itself is one no peer agreed to and one it cannot check for freshness.
func TestRound1RequiresSessionNonce(t *testing.T) {
	setUp("info")

	P, outCh := newNonceTestParty(t, big.NewInt(42), nil)
	tssErr := P.Start()
	if assert.NotNil(t, tssErr, "round 1 must fail when no session nonce is set") {
		assert.Contains(t, tssErr.Error(), "requires a session nonce")
	}
	assert.Equal(t, 0, len(outCh), "a failed round 1 must not emit any message")

	// Paired arm: the same party configuration with a nonce set must run.
	Q, outQ := newNonceTestParty(t, big.NewInt(42), big.NewInt(1))
	assert.Nil(t, Q.Start(), "round 1 must succeed once a session nonce is set")
	assert.Equal(t, testThreshold+1, len(outQ), "round 1 emits N-1 P2P messages and one broadcast")
}

// TestSSIDBindsTheMessage pins the other half of the same change. Everything
// the SSID is built from is fixed by the key material except the nonce and the
// message, so with a reused nonce the message is the only thing keeping two
// runs of one committee apart. A caller holding one Parameters object across
// executions is the shape that makes reuse easiest to reach.
func TestSSIDBindsTheMessage(t *testing.T) {
	setUp("info")

	nonce := big.NewInt(1)
	P1, _ := newNonceTestParty(t, big.NewInt(42), nonce)
	P2, _ := newNonceTestParty(t, big.NewInt(43), nonce)
	P3, _ := newNonceTestParty(t, big.NewInt(42), nonce)
	assert.Nil(t, P1.Start())
	assert.Nil(t, P2.Start())
	assert.Nil(t, P3.Start())

	assert.False(t, bytes.Equal(P1.temp.ssid, P2.temp.ssid),
		"two messages under one nonce must not share an SSID")
	assert.True(t, bytes.Equal(P1.temp.ssid, P3.temp.ssid),
		"the same message under the same nonce must reproduce the SSID")
}
