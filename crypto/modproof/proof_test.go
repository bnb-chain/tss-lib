// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package modproof_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	. "github.com/bnb-chain/tss-lib/v2/crypto/modproof"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/stretchr/testify/assert"
)

var Session = []byte("session")

func TestMod(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N

	proof, err := NewProof(Session, N, P, Q, rand.Reader)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])
	assert.NoError(test, err)

	ok := proof.Verify(Session, N)
	assert.True(test, ok, "proof must verify")
}

var (
	one = big.NewInt(1)
)

func NewHackedProof(Session []byte, N, P *big.Int, Q []*big.Int) (*ProofMod, error) {
	Phi := new(big.Int).Sub(P, one)
	bigQ := new(big.Int).Set(one)
	for _, q := range Q {
		Phi.Mul(Phi, new(big.Int).Sub(q, one))
		bigQ.Mul(bigQ, q)
	}
	invBigQ := new(big.Int).ModInverse(bigQ, P)
	// Now W = 1 mod bigP and W = 0 mod bigQ
	W := new(big.Int).Mul(invBigQ, bigQ)
	// Verify W ≡ 1 (mod P)
	if new(big.Int).Mod(W, P).Cmp(one) != 0 {
		return nil, fmt.Errorf("w is not congruent to 1 modulo p")
	}
	// Verify W ≡ 0 (mod q) for all q in Q
	for _, q := range Q {
		if new(big.Int).Mod(W, q).Cmp(big.NewInt(0)) != 0 {
			return nil, fmt.Errorf("w is not congruent to 0 modulo all values in q")
		}
	}
	// Fig 16.2 - Computing the Y values
	Y := [Iterations]*big.Int{}
	for i := range Y {
		ei := common.SHA512_256i_TAGGED(Session, append([]*big.Int{W, N},
			Y[:i]...)...)
		Y[i] = common.RejectionSample(N, ei)
	}
	// Fig 16.3
	modN, modP := common.ModInt(N), common.ModInt(P)
	// modPhi := common.ModInt(Phi)
	invN := new(big.Int).ModInverse(N, Phi)
	X := [Iterations]*big.Int{}
	// Fix bitLen of A and B
	A := new(big.Int).Lsh(one, Iterations)
	B := new(big.Int).Lsh(one, Iterations)
	Z := [Iterations]*big.Int{}
	// for fourth-root mod p
	expo := new(big.Int).Add(P, one)
	expo = new(big.Int).Rsh(expo, 3)
	for i := range Y {
		B.SetBit(B, i, uint(1))
		Yi := new(big.Int).SetBytes(Y[i].Bytes())
		if big.Jacobi(Yi, P) == 1 {
			A.SetBit(A, i, uint(0))
		} else {
			A.SetBit(A, i, uint(1))
			Yi = modN.Mul(big.NewInt(-1), Yi)
		}
		Xi := modN.Mul(modP.Exp(Yi, expo), W)
		Zi := modN.Exp(Y[i], invN)
		X[i], Z[i] = Xi, Zi
	}
	pf := &ProofMod{W: W, X: X, A: A, B: B, Z: Z}
	return pf, nil
}

func mustSetString(s string) *big.Int {
	i, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("Failed to parse integer: " + s)
	}
	return i
}

func TestAttackMod(test *testing.T) {
	fmt.Printf("Starting TestAttackMod\n")

	// need p % 8 = 7
	P := mustSetString("11956161572522965463")
	fmt.Printf("P = %v\n", P)

	Q := []*big.Int{
		mustSetString("2495927741"),
		mustSetString("3726287311"),
		mustSetString("3756248813"),
		mustSetString("3962607427"),
		mustSetString("2685519289"),
		mustSetString("2316427879"),
		mustSetString("3704490329"),
	}
	fmt.Printf("Q = %v\n", Q)

	N := new(big.Int).SetBytes(P.Bytes())
	for _, q := range Q {
		N.Mul(N, q)
	}
	proof, err := NewHackedProof(Session, N, P, Q)
	assert.NoError(test, err)
	ok := proof.Verify(Session, N)
	assert.Falsef(test, ok, "false proof should not verify")
}
