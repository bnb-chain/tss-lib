// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpmul

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
    testSafePrimeBits = 1024
)

func TestMul(test *testing.T) {
    ec := tss.EC()
    q := ec.Params().N

    sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
    assert.NoError(test, err)

    x := common.GetRandomPositiveInt(q)
    X, rhox, err := sk.EncryptAndReturnRandomness(x)
    assert.NoError(test, err)

	y := common.GetRandomPositiveInt(q)
	Y, _, err := sk.EncryptAndReturnRandomness(y)
	// rho := big.NewInt(1)
	assert.NoError(test, err)

	C, err := pk.HomoMult(x, Y)
	assert.NoError(test, err)

    proof, err := NewProof(ec, pk, X, Y, C, x, rhox)
    assert.NoError(test, err)

    ok := proof.Verify(ec, pk, X, Y, C)
    assert.True(test, ok, "proof must verify")
}
