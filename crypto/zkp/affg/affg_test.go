// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpaffg

import (
    "math/big"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"

    "github.com/binance-chain/tss-lib/common"
    "github.com/binance-chain/tss-lib/crypto"
    "github.com/binance-chain/tss-lib/crypto/paillier"
    "github.com/binance-chain/tss-lib/ecdsa/keygen"
    "github.com/binance-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
    testPaillierKeyLength = 2048
)

func TestAffg(test *testing.T) {
    ec := tss.EC()
    q := ec.Params().N
    q3 := new(big.Int).Mul(q, q)
    q3 = new(big.Int).Mul(q, q3)
    // q6 := new(big.Int).Mul(q3, q3)

    _, pk0, err := paillier.GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
    assert.NoError(test, err)
    _, pk1, err := paillier.GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
    assert.NoError(test, err)

    // a*b+w
    a := common.GetRandomPositiveInt(q)
    x := common.GetRandomPositiveInt(q)
    // x := q6
    y := common.GetRandomPositiveInt(q3)

	X := crypto.ScalarBaseMult(ec, x)
    assert.NoError(test, err)

    Y, rhoy, err := pk1.EncryptAndReturnRandomness(y)
    assert.NoError(test, err)

    NCap, s, t, err := keygen.LoadNTildeH1H2FromTestFixture(1)
    assert.NoError(test, err)

    C, _, err := pk0.EncryptAndReturnRandomness(a)
    assert.NoError(test, err)

    cw, rho, err := pk0.EncryptAndReturnRandomness(y)
    assert.NoError(test, err)

    D, err := pk0.HomoMult(x, C)
    assert.NoError(test, err)
    D, err = pk0.HomoAdd(D, cw)
    assert.NoError(test, err)

    proof, err := NewProof(ec, pk0, pk1, NCap, s, t, C, D, Y, X, x, y, rho, rhoy)
    assert.NoError(test, err)

    ok := proof.Verify(ec, pk0, pk1, NCap, s, t, C, D, Y, X)
    assert.True(test, ok, "proof must verify")

	x = q3
	proof, err = NewProof(ec, pk0, pk1, NCap, s, t, C, D, Y, X, x, y, rho, rhoy)
    assert.NoError(test, err)

    ok = proof.Verify(ec, pk0, pk1, NCap, s, t, C, D, Y, X)
    assert.False(test, ok, "proof must verify")

	x = common.GetRandomPositiveInt(q)
	y = q3
	proof, err = NewProof(ec, pk0, pk1, NCap, s, t, C, D, Y, X, x, y, rho, rhoy)
    assert.NoError(test, err)

    ok = proof.Verify(ec, pk0, pk1, NCap, s, t, C, D, Y, X)
    assert.False(test, ok, "proof must verify")
}
