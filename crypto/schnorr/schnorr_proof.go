// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package schnorr

import (
	"errors"
	"io"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

type (
	ZKProof struct {
		Alpha *crypto.ECPoint
		T     *big.Int
	}

	ZKVProof struct {
		Alpha *crypto.ECPoint
		T, U  *big.Int
	}
)

// Per-proof-type Fiat-Shamir domain separators. See facproof.fsSession
// for the rationale and v3↔v4 wire-incompat note.
const (
	fsDomainTagZK  = "tss-lib.v4.schnorr.zk"
	fsDomainTagZKV = "tss-lib.v4.schnorr.zkv"
)

func fsSessionZK(Session []byte) []byte {
	return append([]byte(fsDomainTagZK+"|"), Session...)
}

func fsSessionZKV(Session []byte) []byte {
	return append([]byte(fsDomainTagZKV+"|"), Session...)
}

// NewZKProof constructs a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func NewZKProof(Session []byte, x *big.Int, X *crypto.ECPoint, rand io.Reader) (*ZKProof, error) {
	if x == nil || X == nil || !X.ValidateBasic() {
		return nil, errors.New("ZKProof constructor received nil or invalid value(s)")
	}
	ec := X.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy) // already on the curve.

	a := common.GetRandomPositiveInt(rand, q)
	alpha := crypto.ScalarBaseMult(ec, a)

	var c *big.Int
	{
		cHash := common.SHA512_256i_TAGGED(fsSessionZK(Session), X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = common.ModReduceHash(q, cHash)
	}

	var t *big.Int
	modQ := common.ModInt(q)
	if common.IsConstantTimeEnabled() {
		// SECURITY: Use constant-time multiplication for secret x
		ctModQ := common.NewCTModInt(q)
		cx := ctModQ.MulCT(c, x)
		t = modQ.Add(a, cx)
	} else {
		t = new(big.Int).Mul(c, x)
		t = modQ.Add(a, t)
	}

	return &ZKProof{Alpha: alpha, T: t}, nil
}

// NewZKProof verifies a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func (pf *ZKProof) Verify(Session []byte, X *crypto.ECPoint) bool {
	// ValidateInSubgroup rejects (a) nil / off-curve, (b) the Edwards
	// identity (0, 1), and (c) on composite-cofactor curves, any
	// low-order point outside the prime-order subgroup. The last
	// closes the small-subgroup attack on Schnorr Alpha — Alpha does
	// not go through EightInvEight, unlike VSS commitments in the
	// EdDSA protocol path.
	if pf == nil || X == nil || !X.ValidateInSubgroup() || pf.Alpha == nil || !pf.Alpha.ValidateInSubgroup() || pf.T == nil {
		return false
	}
	// Both X and Alpha must live on the same curve as each other (and as
	// the implicit ec derived from X.Curve()). Direct API consumers can
	// construct ECPoints with NewECPointNoCurveCheck on a different curve,
	// and the hash transcript / scalar mult below silently mix curves
	// without this guard.
	if !tss.SameCurve(X.Curve(), pf.Alpha.Curve()) {
		return false
	}
	ec := X.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	if !isValidScalar(pf.T, q) {
		return false
	}
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{
		cHash := common.SHA512_256i_TAGGED(fsSessionZK(Session), X.X(), X.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = common.ModReduceHash(q, cHash)
	}
	if c.Sign() == 0 {
		return false
	}
	tG := crypto.ScalarBaseMult(ec, pf.T)
	Xc := X.ScalarMult(c)
	if tG == nil || Xc == nil {
		return false
	}
	aXc, err := pf.Alpha.Add(Xc)
	if err != nil {
		return false
	}
	return aXc.X().Cmp(tG.X()) == 0 && aXc.Y().Cmp(tG.Y()) == 0
}

func (pf *ZKProof) ValidateBasic() bool {
	return pf.T != nil && pf.Alpha != nil && pf.Alpha.ValidateBasic()
}

// NewZKProof constructs a new Schnorr ZK proof of knowledge s_i, l_i such that V_i = R^s_i, g^l_i (GG18Spec Fig. 17)
func NewZKVProof(Session []byte, V, R *crypto.ECPoint, s, l *big.Int, rand io.Reader) (*ZKVProof, error) {
	if V == nil || R == nil || s == nil || l == nil || !V.ValidateBasic() || !R.ValidateBasic() {
		return nil, errors.New("ZKVProof constructor received nil value(s)")
	}
	ec := V.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	a, b := common.GetRandomPositiveInt(rand, q), common.GetRandomPositiveInt(rand, q)
	aR := R.ScalarMult(a)
	bG := crypto.ScalarBaseMult(ec, b)
	alpha, _ := aR.Add(bG) // already on the curve.

	var c *big.Int
	{
		cHash := common.SHA512_256i_TAGGED(fsSessionZKV(Session), V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = common.ModReduceHash(q, cHash)
	}
	modQ := common.ModInt(q)

	var t, u *big.Int
	if common.IsConstantTimeEnabled() {
		// SECURITY: Use constant-time multiplication for secret values s and l
		ctModQ := common.NewCTModInt(q)
		cs := ctModQ.MulCT(c, s)
		cl := ctModQ.MulCT(c, l)
		t = modQ.Add(a, cs)
		u = modQ.Add(b, cl)
	} else {
		t = modQ.Add(a, new(big.Int).Mul(c, s))
		u = modQ.Add(b, new(big.Int).Mul(c, l))
	}

	return &ZKVProof{Alpha: alpha, T: t, U: u}, nil
}

func (pf *ZKVProof) Verify(Session []byte, V, R *crypto.ECPoint) bool {
	// ValidateInSubgroup on all three caller-supplied points enforces
	// the same identity / low-order rejection as ZKProof.Verify above.
	if pf == nil || V == nil || R == nil ||
		!V.ValidateInSubgroup() || !R.ValidateInSubgroup() ||
		pf.Alpha == nil || !pf.Alpha.ValidateInSubgroup() ||
		pf.T == nil || pf.U == nil {
		return false
	}
	// All three caller-supplied points must agree on the curve so the hash
	// transcript and scalar mults below stay consistent.
	if !tss.SameCurve(V.Curve(), R.Curve()) || !tss.SameCurve(V.Curve(), pf.Alpha.Curve()) {
		return false
	}
	ec := V.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	if !isValidScalar(pf.T, q) || !isValidScalar(pf.U, q) {
		return false
	}
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{
		cHash := common.SHA512_256i_TAGGED(fsSessionZKV(Session), V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = common.ModReduceHash(q, cHash)
	}
	if c.Sign() == 0 {
		return false
	}
	tR := R.ScalarMult(pf.T)
	uG := crypto.ScalarBaseMult(ec, pf.U)
	if tR == nil || uG == nil {
		return false
	}
	tRuG, err := tR.Add(uG)
	if err != nil {
		return false
	}

	Vc := V.ScalarMult(c)
	if Vc == nil {
		return false
	}
	aVc, err := pf.Alpha.Add(Vc)
	if err != nil {
		return false
	}
	return tRuG.X().Cmp(aVc.X()) == 0 && tRuG.Y().Cmp(aVc.Y()) == 0
}

func (pf *ZKVProof) ValidateBasic() bool {
	return pf.Alpha != nil && pf.T != nil && pf.U != nil && pf.Alpha.ValidateBasic()
}

func isValidScalar(k, q *big.Int) bool {
	return k != nil && k.Sign() > 0 && k.Cmp(q) < 0
}
