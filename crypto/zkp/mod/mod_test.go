// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpmod_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	. "github.com/binance-chain/tss-lib/crypto/zkp/mod"
	"github.com/stretchr/testify/assert"
)

func TestMod(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	p, q, N := preParams.P, preParams.Q, preParams.NTildei
	p2, q2 := new(big.Int).Mul(p, big.NewInt(2)), new(big.Int).Mul(q, big.NewInt(2))
	P, Q := new(big.Int).Add(p2, big.NewInt(1)), new(big.Int).Add(q2, big.NewInt(1))

	proof, err := NewProof(N, P, Q)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])
	assert.NoError(test, err)
	
	ok := proof.Verify(N)
	assert.True(test, ok, "proof must verify")
}
