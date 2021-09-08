// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
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
    // q3 := new(big.Int).Mul(q, q)
    // q3 = new(big.Int).Mul(q, q3)
    // q6 := new(big.Int).Mul(q3, q3)

    _, pki, err := paillier.GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
    assert.NoError(test, err)
    skj, pkj, err := paillier.GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
    assert.NoError(test, err)

    // gammai * kj == betai + alphaj
    kj := common.GetRandomPositiveInt(q)
    Kj, err := pkj.Encrypt(kj)
    assert.NoError(test, err)

    gammai := common.GetRandomPositiveInt(q)
    BigGammai := crypto.ScalarBaseMult(ec, gammai)

    NCap, s, t, err := keygen.LoadNTildeH1H2FromTestFixture(1)
    assert.NoError(test, err)

    MtaOut, err := NewMtA(ec, Kj, gammai, BigGammai, pkj, pki, NCap, s, t)
    assert.NoError(test, err)

    alphaj, err := skj.Decrypt(MtaOut.Dji)
    assert.NoError(test, err)
    betai := MtaOut.Beta
    
    modN := common.ModInt(ec.Params().N)
    lhs := modN.Add(alphaj, betai)
    rhs := modN.Mul(kj, gammai)
    test.Log(lhs, rhs)
    assert.Equal(test, 0, lhs.Cmp(rhs))
    ok := MtaOut.Proofji.Verify(ec, pkj, pki, NCap, s, t, Kj, MtaOut.Dji, MtaOut.Fji, BigGammai)
    assert.True(test, ok)
}