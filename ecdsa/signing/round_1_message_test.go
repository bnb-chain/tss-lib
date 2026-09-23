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

// TestRound1RejectsMessageHashOutsideZq pins both ends of the interval the
// hashed message must lie in, together with the honest edge cases that must
// keep working. Round 1 historically checked only the upper end; values at the
// bottom of the range are not rejected anywhere downstream, so the check has to
// be complete here.
func TestRound1RejectsMessageHashOutsideZq(t *testing.T) {
	setUp("info")

	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")

	p2pCtx := tss.NewPeerContext(signPIDs)
	q := tss.S256().Params().N

	newParty := func(m *big.Int) *LocalParty {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[0], len(signPIDs), testThreshold)
		params.SetSessionNonce(big.NewInt(1))
		outCh := make(chan tss.Message, 16)
		endCh := make(chan *common.SignatureData, 1)
		return NewLocalParty(m, params, keys[0], outCh, endCh).(*LocalParty)
	}

	rejected := []struct {
		name string
		m    *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"negative", big.NewInt(-1)},
		{"equal to the group order", new(big.Int).Set(q)},
		{"above the group order", new(big.Int).Add(q, big.NewInt(1))},
	}
	for _, tc := range rejected {
		tssErr := newParty(tc.m).Start()
		if assert.NotNil(t, tssErr, "must be rejected: %s", tc.name) {
			assert.Contains(t, tssErr.Error(), "hashed message is not valid", tc.name)
		}
	}

	accepted := []struct {
		name string
		m    *big.Int
	}{
		{"smallest legal value", big.NewInt(1)},
		{"ordinary value", big.NewInt(42)},
		{"value with a leading zero byte", new(big.Int).SetBytes([]byte{0x00, 0xf1, 0x63, 0xee, 0x51, 0xbc})},
		{"largest legal value", new(big.Int).Sub(q, big.NewInt(1))},
	}
	for _, tc := range accepted {
		assert.Nil(t, newParty(tc.m).Start(), "must be accepted: %s", tc.name)
	}
}
