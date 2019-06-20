package schnorr_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto"
	. "github.com/binance-chain/tss-lib/crypto/schnorr"
	"github.com/binance-chain/tss-lib/tss"
)

func TestSchnorrProof(t *testing.T) {
	q := tss.EC().Params().N
	u := random.GetRandomPositiveInt(q)
	uG := crypto.ScalarBaseMult(tss.EC(), u)
	proof := NewZKProof(u, uG)

	assert.True(t, proof.Alpha.IsOnCurve(tss.EC()))
	assert.NotZero(t, proof.Alpha.X())
	assert.NotZero(t, proof.Alpha.Y())
	assert.NotZero(t, proof.T)
}

func TestSchnorrProofVerify(t *testing.T) {
	q := tss.EC().Params().N
	u := random.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	proof := NewZKProof(u, X)
	res := proof.Verify(X)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrProofVerifyBad(t *testing.T) {
	q := tss.EC().Params().N
	u  := random.GetRandomPositiveInt(q)
	u2 := random.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)
	X2 := crypto.ScalarBaseMult(tss.EC(), u2)

	proof := NewZKProof(u2, X2)
	res := proof.Verify(X)

	assert.False(t, res, "verify result must be false")
}

func TestSchnorrVProofVerify(t *testing.T) {
	t.Skip("WIP")

	q := tss.EC().Params().N
	k := random.GetRandomPositiveInt(q)
	s := random.GetRandomPositiveInt(q)
	l := random.GetRandomPositiveInt(q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(tss.EC(), s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V := Rs.Add(tss.EC(), lG)

	proof := NewZKVProof(V, R, s, l)
	res := proof.Verify(V, R)

	assert.True(t, res, "verify result must be true")
}
