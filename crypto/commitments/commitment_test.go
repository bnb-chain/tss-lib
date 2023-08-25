// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package commitments_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/bnb-chain/tss-lib/v2/crypto/commitments"
)

func TestCreateVerify(t *testing.T) {
	one := big.NewInt(1)
	zero := big.NewInt(0)

	commitment := NewHashCommitment(zero, one)
	pass := commitment.Verify()

	assert.True(t, pass, "must pass")
}

func TestDeCommit(t *testing.T) {
	one := big.NewInt(1)
	zero := big.NewInt(0)

	commitment := NewHashCommitment(zero, one)
	pass, secrets := commitment.DeCommit()

	assert.True(t, pass, "must pass")

	assert.NotZero(t, len(secrets), "len(secrets) must be non-zero")
}
