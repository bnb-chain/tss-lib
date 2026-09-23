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
	"github.com/bnb-chain/tss-lib/v4/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

func newNonceTestParty(t *testing.T, m, nonce *big.Int) (*LocalParty, chan tss.Message) {
	t.Helper()
	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	assert.NoError(t, err, "should load keygen fixtures")
	params := tss.NewParameters(tss.Edwards(), tss.NewPeerContext(signPIDs), signPIDs[0], len(signPIDs), testThreshold)
	if nonce != nil {
		params.SetSessionNonce(nonce)
	}
	outCh := make(chan tss.Message, 16)
	endCh := make(chan *common.SignatureData, 1)
	return NewLocalParty(m, params, keys[0], outCh, endCh).(*LocalParty), outCh
}

// TestRound1RequiresSessionNonce pins the fail-closed contract on the EdDSA
// side; see the ECDSA test of the same name.
func TestRound1RequiresSessionNonce(t *testing.T) {
	setUp("info")

	P, outCh := newNonceTestParty(t, big.NewInt(200), nil)
	tssErr := P.Start()
	if assert.NotNil(t, tssErr, "round 1 must fail when no session nonce is set") {
		assert.Contains(t, tssErr.Error(), "requires a session nonce")
	}
	assert.Equal(t, 0, len(outCh), "a failed round 1 must not emit any message")

	Q, outQ := newNonceTestParty(t, big.NewInt(200), big.NewInt(1))
	assert.Nil(t, Q.Start(), "round 1 must succeed once a session nonce is set")
	assert.Equal(t, 1, len(outQ), "round 1 broadcasts one commitment")
}

// TestRound1RejectsAbsentMessage covers what the removed nonce fallback used
// to do by accident: it was the only thing that touched the message early
// enough to fail before anything was broadcast. Without an explicit check a
// nil message survives two broadcast rounds and takes down a round-3 goroutine
// instead.
func TestRound1RejectsAbsentMessage(t *testing.T) {
	setUp("info")

	for _, tc := range []struct {
		name string
		m    *big.Int
		want string
	}{
		{"nil", nil, "message to sign is nil"},
		{"negative", big.NewInt(-1), "message to sign is negative"},
	} {
		P, outCh := newNonceTestParty(t, tc.m, big.NewInt(1))
		tssErr := P.Start()
		if assert.NotNil(t, tssErr, "must be rejected: %s", tc.name) {
			assert.Contains(t, tssErr.Error(), tc.want, tc.name)
		}
		assert.Equal(t, 0, len(outCh), "a failed round 1 must not emit any message: %s", tc.name)
	}

	// Honest messages, including the empty one and one with leading zero
	// bytes, must keep working.
	for _, tc := range []struct {
		name string
		m    *big.Int
	}{
		{"empty message", big.NewInt(0)},
		{"small message", big.NewInt(200)},
		{"leading zero bytes", new(big.Int).SetBytes([]byte{0x00, 0xf1, 0x63, 0xee})},
		{"32-byte message", new(big.Int).Lsh(big.NewInt(1), 255)},
	} {
		P, _ := newNonceTestParty(t, tc.m, big.NewInt(1))
		assert.Nil(t, P.Start(), "must be accepted: %s", tc.name)
	}
}

// TestSSIDBindsTheMessage; see the ECDSA test of the same name.
func TestSSIDBindsTheMessage(t *testing.T) {
	setUp("info")

	nonce := big.NewInt(1)
	P1, _ := newNonceTestParty(t, big.NewInt(200), nonce)
	P2, _ := newNonceTestParty(t, big.NewInt(201), nonce)
	P3, _ := newNonceTestParty(t, big.NewInt(200), nonce)
	assert.Nil(t, P1.Start())
	assert.Nil(t, P2.Start())
	assert.Nil(t, P3.Start())

	assert.False(t, bytes.Equal(P1.temp.ssid, P2.temp.ssid),
		"two messages under one nonce must not share an SSID")
	assert.True(t, bytes.Equal(P1.temp.ssid, P3.temp.ssid),
		"the same message under the same nonce must reproduce the SSID")
}
