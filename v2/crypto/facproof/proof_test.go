// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package facproof_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	. "github.com/bnb-chain/tss-lib/v2/crypto/facproof"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

var (
	Session = []byte("session")
)

func TestFac(test *testing.T) {
	ec := tss.EC()

	N0p := common.GetRandomPrimeInt(testSafePrimeBits)
	N0q := common.GetRandomPrimeInt(testSafePrimeBits)
	N0 := new(big.Int).Mul(N0p, N0q)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	assert.NoError(test, err)
	proof, err := NewProof(Session, ec, N0, NCap, s, t, N0p, N0q)
	assert.NoError(test, err)

	ok := proof.Verify(Session, ec, N0, NCap, s, t)
	assert.True(test, ok, "proof must verify")

	N0p = common.GetRandomPrimeInt(1024)
	N0q = common.GetRandomPrimeInt(1024)
	N0 = new(big.Int).Mul(N0p, N0q)

	proof, err = NewProof(Session, ec, N0, NCap, s, t, N0p, N0q)
	assert.NoError(test, err)

	ok = proof.Verify(Session, ec, N0, NCap, s, t)
	assert.True(test, ok, "proof must verify")
}
