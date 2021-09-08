// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkplogstar

import (
    "math/big"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"

    "github.com/binance-chain/tss-lib/common"
    "github.com/binance-chain/tss-lib/crypto"
    "github.com/binance-chain/tss-lib/crypto/paillier"
    "github.com/binance-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
    testSafePrimeBits = 1024
)

func TestLogstar(test *testing.T) {
    ec := tss.EC()
    q := ec.Params().N

    sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
    assert.NoError(test, err)

    x := common.GetRandomPositiveInt(q)
    C, rho, err := sk.EncryptAndReturnRandomness(x)
    assert.NoError(test, err)
    X := crypto.ScalarBaseMult(ec, x)

    primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
    NCap, s, t, err := crypto.GenerateNTildei(primes)
    assert.NoError(test, err)

    g := crypto.ScalarBaseMult(ec, big.NewInt(1))
    proof, err := NewProof(ec, pk, C, X, g, NCap, s, t, x, rho)
    assert.NoError(test, err)

    ok := proof.Verify(ec, pk, C, X, g, NCap, s, t)
    assert.True(test, ok, "proof must verify")
}
