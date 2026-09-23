// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
)

// The four decommitment fields whose length is a function of the threshold are
// the four NonEmptyMultiBytes call sites in this library that pass no expected
// length. That is not an oversight to correct at the message layer: the message
// layer does not know the threshold, so there is no constant to pass. This pins
// the state of the message layer so that a later reader does not "fix" it there
// and conclude the count is bounded before the round sees it.
func TestDeCommitmentCountIsNotBoundedByTheMessageLayer(t *testing.T) {
	m := &KGRound2Message2{DeCommitment: make([][]byte, 100000)}
	for i := range m.DeCommitment {
		m.DeCommitment[i] = []byte{1}
	}
	assert.True(t, m.ValidateBasic(),
		"ValidateBasic cannot bound this count -- the bound is (t+1)*2+1 and it does "+
			"not know t; round 3 is where the check has to live")

	// And the helper it calls is the reason: with no expected length it only
	// requires every part to be non-empty.
	assert.True(t, common.NonEmptyMultiBytes(m.DeCommitment))
	assert.False(t, common.NonEmptyMultiBytes(m.DeCommitment, 7))
}
