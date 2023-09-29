// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package schnorr_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	. "github.com/bnb-chain/tss-lib/v2/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

var Session = []byte("session")

func TestSchnorrProof(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	uG := crypto.ScalarBaseMult(tss.EC(), u)
	proof, _ := NewZKProof(Session, u, uG, rand.Reader)

	assert.True(t, proof.Alpha.IsOnCurve())
	assert.NotZero(t, proof.Alpha.X())
	assert.NotZero(t, proof.Alpha.Y())
	assert.NotZero(t, proof.T)
}

func TestSchnorrProofVerify(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	proof, _ := NewZKProof(Session, u, X, rand.Reader)
	res := proof.Verify(Session, X)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrProofVerifyBadX(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	u2 := common.GetRandomPositiveInt(rand.Reader, q)
	X := crypto.ScalarBaseMult(tss.EC(), u)
	X2 := crypto.ScalarBaseMult(tss.EC(), u2)

	proof, _ := NewZKProof(Session, u2, X2, rand.Reader)
	res := proof.Verify(Session, X)

	assert.False(t, res, "verify result must be false")
}

func TestSchnorrVProofVerify(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(rand.Reader, q)
	s := common.GetRandomPositiveInt(rand.Reader, q)
	l := common.GetRandomPositiveInt(rand.Reader, q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, _ := Rs.Add(lG)

	proof, _ := NewZKVProof(Session, V, R, s, l, rand.Reader)
	res := proof.Verify(Session, V, R)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrVProofVerifyBadPartialV(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(rand.Reader, q)
	s := common.GetRandomPositiveInt(rand.Reader, q)
	l := common.GetRandomPositiveInt(rand.Reader, q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	V := Rs

	proof, _ := NewZKVProof(Session, V, R, s, l, rand.Reader)
	res := proof.Verify(Session, V, R)

	assert.False(t, res, "verify result must be false")
}

func TestSchnorrVProofVerifyBadS(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(rand.Reader, q)
	s := common.GetRandomPositiveInt(rand.Reader, q)
	s2 := common.GetRandomPositiveInt(rand.Reader, q)
	l := common.GetRandomPositiveInt(rand.Reader, q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, _ := Rs.Add(lG)

	proof, _ := NewZKVProof(Session, V, R, s2, l, rand.Reader)
	res := proof.Verify(Session, V, R)

	assert.False(t, res, "verify result must be false")
}
