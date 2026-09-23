// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// Coverage for the output bound applied by AliceEnd and AliceEndWC.
//
// The range proofs verified beforehand bound the magnitude of the prover's
// responses, which does not by itself bound the value produced by the
// decryption. A counterparty that departs from the protocol when choosing its
// additive mask can therefore hand back a plaintext far outside the range a
// conforming run produces, and the reduction mod q would otherwise absorb it
// silently.
//
// These tests pin three properties:
//   - an out-of-range plaintext is rejected, at both AliceEnd and AliceEndWC;
//   - an in-range plaintext is still accepted, so the bound is not a blanket
//     rejection of anything unusual;
//   - all rejections surface as the same error.

type mtaBoundsParty struct {
	sk             *paillier.PrivateKey
	pk             *paillier.PublicKey
	NTilde, h1, h2 *big.Int
}

func loadMtABoundsParty(t *testing.T) *mtaBoundsParty {
	t.Helper()
	fx, _, err := keygen.LoadKeygenTestFixtures(1)
	assert.NoError(t, err)
	f := fx[0]
	return &mtaBoundsParty{
		sk:     f.PaillierSK,
		pk:     &f.PaillierSK.PublicKey,
		NTilde: f.NTildei,
		h1:     f.H1i,
		h2:     f.H2i,
	}
}

// mtaBoundsInputs returns the two multiplicands: `a` belongs to the decrypting
// party, `b` to the counterparty constructing the ciphertext.
func mtaBoundsInputs(t *testing.T) (a, b *big.Int) {
	t.Helper()
	q := tss.EC().Params().N
	a = big.NewInt(0xC0FFEE)
	b, ok := new(big.Int).SetString("d1ce0ff1ce0fbadc0ffee0ddf00d1235", 16)
	assert.True(t, ok)
	assert.Equal(t, -1, a.Cmp(q))
	assert.Equal(t, -1, b.Cmp(q))
	return a, b
}

// buildCiphertextWithMask assembles cB = Enc(a*b - mask mod N) with the local
// witness set to -mask. Nothing negative is transmitted: the witness stays with
// the constructing party, and cB is an ordinary ciphertext.
func buildCiphertextWithMask(t *testing.T, p *mtaBoundsParty, a, b, mask *big.Int) (cA, cB, cRand, betaPrm *big.Int) {
	t.Helper()

	cA, _, err := p.pk.EncryptAndReturnRandomness(rand.Reader, a)
	assert.NoError(t, err)

	betaPrm = new(big.Int).Neg(mask)
	// Encrypt takes nonnegative plaintexts, so the positive representative is
	// what gets encrypted; homomorphically the effect is the same.
	encPlain := new(big.Int).Mod(betaPrm, p.pk.N)
	cBetaPrm, r, err := p.pk.EncryptAndReturnRandomness(rand.Reader, encPlain)
	assert.NoError(t, err)
	cRand = r

	cB, err = p.pk.HomoMult(b, cA)
	assert.NoError(t, err)
	cB, err = p.pk.HomoAdd(cB, cBetaPrm)
	assert.NoError(t, err)

	return cA, cB, cRand, betaPrm
}

// maskAboveProduct puts the mask strictly above a*b, so the plaintext leaves the
// range a conforming run produces.
func maskAboveProduct(a, b *big.Int) *big.Int {
	return new(big.Int).Mul(new(big.Int).Add(a, big.NewInt(1)), b)
}

// maskBelowProduct puts the mask strictly below a*b, so the plaintext stays in
// range and the additive share is arithmetically correct.
func maskBelowProduct(a, b *big.Int) *big.Int {
	return new(big.Int).Mul(new(big.Int).Sub(a, big.NewInt(1)), b)
}

func TestAliceEndWCRejectsOutOfRangePlaintext(t *testing.T) {
	// The counterparty is assumed to run its own prover; the verifier side is
	// independent of this setting.
	common.DisableConstantTimeOps()
	defer common.EnableConstantTimeOps()

	p := loadMtABoundsParty(t)
	ec := tss.EC()
	a, b := mtaBoundsInputs(t)
	B := crypto.ScalarBaseMult(ec, b)

	cA, cB, cRand, betaPrm := buildCiphertextWithMask(t, p, a, b, maskAboveProduct(a, b))

	pf, err := ProveBobWC(Session, ec, p.pk, p.NTilde, p.h1, p.h2, cA, cB, b, betaPrm, cRand, B, rand.Reader)
	assert.NoError(t, err)

	// Precondition: the range proof is not what stops this, so the output bound
	// is doing real work rather than shadowing an earlier check.
	assert.True(t, pf.Verify(Session, ec, p.pk, p.NTilde, p.h1, p.h2, cA, cB, B),
		"precondition: ProofBobWC.Verify accepts this transcript")

	alpha, err := AliceEndWC(Session, ec, p.pk, pf, B, cA, cB, p.NTilde, p.h1, p.h2, p.sk)
	assert.Error(t, err, "an out-of-range plaintext must be rejected after decryption")
	assert.Nil(t, alpha, "no share may be returned for a rejected instance")
}

// TestAliceEndRejectsOutOfRangePlaintext covers the second call site. It is
// reached independently of the "with check" variant, so a bound applied to only
// one of the two would leave this one uncovered.
func TestAliceEndRejectsOutOfRangePlaintext(t *testing.T) {
	common.DisableConstantTimeOps()
	defer common.EnableConstantTimeOps()

	p := loadMtABoundsParty(t)
	ec := tss.EC()
	a, b := mtaBoundsInputs(t)

	cA, cB, cRand, betaPrm := buildCiphertextWithMask(t, p, a, b, maskAboveProduct(a, b))

	pf, err := ProveBob(Session, ec, p.pk, p.NTilde, p.h1, p.h2, cA, cB, b, betaPrm, cRand, rand.Reader)
	assert.NoError(t, err)
	assert.True(t, pf.Verify(Session, ec, p.pk, p.NTilde, p.h1, p.h2, cA, cB),
		"precondition: ProofBob.Verify accepts this transcript")

	alpha, err := AliceEnd(Session, ec, p.pk, pf, p.h1, p.h2, cA, cB, p.NTilde, p.sk)
	assert.Error(t, err, "the second call site must apply the same bound")
	assert.Nil(t, alpha)
}

// TestAliceEndWCAcceptsInRangePlaintext documents the scope of the bound: it
// rejects values outside the range, and nothing else. A mask below the product
// leaves the plaintext in range and the MtA output correct, and must pass.
func TestAliceEndWCAcceptsInRangePlaintext(t *testing.T) {
	common.DisableConstantTimeOps()
	defer common.EnableConstantTimeOps()

	p := loadMtABoundsParty(t)
	ec := tss.EC()
	q := ec.Params().N
	a, b := mtaBoundsInputs(t)
	B := crypto.ScalarBaseMult(ec, b)

	cA, cB, cRand, betaPrm := buildCiphertextWithMask(t, p, a, b, maskBelowProduct(a, b))

	pf, err := ProveBobWC(Session, ec, p.pk, p.NTilde, p.h1, p.h2, cA, cB, b, betaPrm, cRand, B, rand.Reader)
	assert.NoError(t, err)

	alpha, err := AliceEndWC(Session, ec, p.pk, pf, B, cA, cB, p.NTilde, p.h1, p.h2, p.sk)
	assert.NoError(t, err, "an in-range plaintext must not be rejected")

	// alpha + beta == a*b (mod q): the MtA output is correct here.
	beta := common.ModInt(q).Sub(big.NewInt(0), betaPrm)
	lhs := common.ModInt(q).Add(alpha, beta)
	rhs := new(big.Int).Mod(new(big.Int).Mul(a, b), q)
	assert.Equal(t, 0, lhs.Cmp(rhs), "in-range: the additive share is arithmetically correct")
}

// TestAliceEndRejectionsAreIndistinguishable pins that a failed proof and an
// out-of-range plaintext surface as the same error, so the peer cannot tell
// which check declined.
func TestAliceEndRejectionsAreIndistinguishable(t *testing.T) {
	common.DisableConstantTimeOps()
	defer common.EnableConstantTimeOps()

	p := loadMtABoundsParty(t)
	ec := tss.EC()
	a, b := mtaBoundsInputs(t)
	B := crypto.ScalarBaseMult(ec, b)

	cA, cB, cRand, betaPrm := buildCiphertextWithMask(t, p, a, b, maskAboveProduct(a, b))
	pf, err := ProveBobWC(Session, ec, p.pk, p.NTilde, p.h1, p.h2, cA, cB, b, betaPrm, cRand, B, rand.Reader)
	assert.NoError(t, err)

	// (1) declined because the plaintext is out of range
	_, errRange := AliceEndWC(Session, ec, p.pk, pf, B, cA, cB, p.NTilde, p.h1, p.h2, p.sk)
	assert.Error(t, errRange)

	// (2) declined because the proof does not verify (bound to a different point)
	otherB := crypto.ScalarBaseMult(ec, new(big.Int).Add(b, big.NewInt(1)))
	_, errProof := AliceEndWC(Session, ec, p.pk, pf, otherB, cA, cB, p.NTilde, p.h1, p.h2, p.sk)
	assert.Error(t, errProof)

	assert.Equal(t, errProof, errRange,
		"the two rejection causes must not be distinguishable to the peer")
}

// TestAlphaPrmRangeBoundary pins the window. A conforming run produces
// alphaPrm = a*b + betaPrm < q^4 + q^5 < q^6, and the modulus is at least
// 2^2047, so the cut has wide margin on both sides.
func TestAlphaPrmRangeBoundary(t *testing.T) {
	q := tss.EC().Params().N
	q4 := new(big.Int).Exp(q, big.NewInt(4), nil)
	q5 := new(big.Int).Exp(q, big.NewInt(5), nil)
	q6 := new(big.Int).Exp(q, big.NewInt(6), nil)

	conformingCeiling := new(big.Int).Add(q4, q5) // strict upper bound in a conforming run

	for _, tc := range []struct {
		name  string
		v     *big.Int
		valid bool
	}{
		{"negative", big.NewInt(-1), false},
		{"zero", big.NewInt(0), true},
		{"small value", big.NewInt(1 << 20), true},
		{"conforming ceiling a*b+betaPrm", conformingCeiling, true},
		{"q^6 - 1", new(big.Int).Sub(q6, big.NewInt(1)), true},
		{"q^6 exactly", q6, false},
		{"value near the modulus", new(big.Int).Exp(big.NewInt(2), big.NewInt(2040), nil), false},
	} {
		assert.Equal(t, tc.valid, alphaPrmInRange(tc.v, q), tc.name)
	}

	assert.Equal(t, -1, conformingCeiling.Cmp(q6), "the conforming ceiling sits strictly below the cut")
}
