// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpenc

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

func TestEnc(test *testing.T) {
    ec := tss.EC()
    q := ec.Params().N

    sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
    assert.NoError(test, err)

    k := common.GetRandomPositiveInt(q)
    K, rho, err := sk.EncryptAndReturnRandomness(k)
    assert.NoError(test, err)

    primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
    NCap, s, t, err := crypto.GenerateNTildei(primes)
    assert.NoError(test, err)
    proof, err := NewProof(ec, pk, K, NCap, s, t, k, rho)
    assert.NoError(test, err)

    ok := proof.Verify(ec, pk, NCap, s, t, K)
    assert.True(test, ok, "proof must verify")
}
