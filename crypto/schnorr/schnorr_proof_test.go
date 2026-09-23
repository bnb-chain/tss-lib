// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package schnorr_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	. "github.com/bnb-chain/tss-lib/v4/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/v4/tss"
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

func TestSchnorrProofVerifyRejectsInvalidInputs(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	X := crypto.ScalarBaseMult(tss.EC(), u)
	proof, _ := NewZKProof(Session, u, X, rand.Reader)

	assert.False(t, proof.Verify(Session, crypto.NewECPointNoCurveCheck(tss.EC(), big.NewInt(1), big.NewInt(1))))

	proof.T = big.NewInt(0)
	assert.NotPanics(t, func() {
		assert.False(t, proof.Verify(Session, X))
	})
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

func TestSchnorrVProofVerifyRejectsZeroScalars(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(rand.Reader, q)
	s := common.GetRandomPositiveInt(rand.Reader, q)
	l := common.GetRandomPositiveInt(rand.Reader, q)
	R := crypto.ScalarBaseMult(tss.EC(), k)
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, _ := Rs.Add(lG)

	proof, _ := NewZKVProof(Session, V, R, s, l, rand.Reader)
	proof.T = big.NewInt(0)
	assert.NotPanics(t, func() {
		assert.False(t, proof.Verify(Session, V, R))
	})

	proof, _ = NewZKVProof(Session, V, R, s, l, rand.Reader)
	proof.U = big.NewInt(0)
	assert.NotPanics(t, func() {
		assert.False(t, proof.Verify(Session, V, R))
	})
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

// TestSchnorrEdwardsIdentityRejected covers Verify rejecting an Edwards
// identity point (0, 1) supplied as either X or Alpha. The identity is
// on-curve for Ed25519 (unlike Weierstrass curves, where it is the
// point-at-infinity and naturally off-curve), so without the
// ValidateBasic identity check it would slip past on-curve validation.
func TestSchnorrEdwardsIdentityRejected(t *testing.T) {
	ec := tss.Edwards()
	q := ec.Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	X := crypto.ScalarBaseMult(ec, u)
	identity := crypto.NewECPointNoCurveCheck(ec, big.NewInt(0), big.NewInt(1))
	assert.True(t, identity.IsOnCurve(), "sanity: Edwards (0,1) must be on-curve")
	assert.True(t, identity.IsIdentity(), "sanity: Edwards (0,1) must report identity")

	t.Run("X = identity", func(tt *testing.T) {
		proof, err := NewZKProof(Session, big.NewInt(0), X, rand.Reader)
		assert.NoError(tt, err)
		assert.False(tt, proof.Verify(Session, identity))
	})
	t.Run("Alpha = identity", func(tt *testing.T) {
		proof, err := NewZKProof(Session, u, X, rand.Reader)
		assert.NoError(tt, err)
		proof.Alpha = identity
		assert.False(tt, proof.Verify(Session, X))
	})
}

// TestSchnorrCurveMismatch covers Verify rejecting Alpha and X on
// different curves. NewECPointNoCurveCheck lets direct API consumers
// build cross-curve mismatches; the verifier must catch this.
func TestSchnorrCurveMismatch(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	X := crypto.ScalarBaseMult(tss.EC(), u)
	proof, err := NewZKProof(Session, u, X, rand.Reader)
	assert.NoError(t, err)

	// Move Alpha to a different curve while keeping the same coordinates.
	alphaOnEdwards := crypto.NewECPointNoCurveCheck(tss.Edwards(), proof.Alpha.X(), proof.Alpha.Y())
	proof.Alpha = alphaOnEdwards
	assert.False(t, proof.Verify(Session, X))
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
