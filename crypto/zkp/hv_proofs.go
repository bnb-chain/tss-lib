// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkp

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

type (
	// ZK proof of knowledge of sigma_i, l_i such that T_i = g^sigma_i, h^l_i (GG20)
	TProof struct {
		Alpha *crypto.ECPoint
		T, U  *big.Int
	}

	// ZK proof for knowledge of sigma_i, l_i such that S_i = R^sigma_i, T_i = g^sigma_i h^l_i (GG20)
	STProof struct {
		Alpha, Beta *crypto.ECPoint
		T, U        *big.Int
	}
)

// NewTProof constructs a new ZK proof of knowledge sigma_i, l_i such that T_i = g^sigma_i, h^l_i (GG20)
func NewTProof(TI, h *crypto.ECPoint, sigmaI, lI *big.Int) (*TProof, error) {
	if TI == nil || h == nil || sigmaI == nil || lI == nil ||
		!TI.ValidateBasic() || !h.ValidateBasic() {
		return nil, errors.New("NewTProof received nil or invalid value(s)")
	}
	ec := tss.EC()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	a, b := common.GetRandomPositiveInt(q), common.GetRandomPositiveInt(q)
	aG, bH := crypto.ScalarBaseMult(ec, a), h.ScalarMult(b)
	alpha, _ := aG.Add(bH) // already on the curve.

	var c *big.Int
	{
		cHash := common.SHA512_256i(
			TI.X(), TI.Y(), h.X(), h.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	t, u := calculateTAndU(q, a, c, sigmaI, b, lI)
	return &TProof{Alpha: alpha, T: t, U: u}, nil
}

func (pf *TProof) Verify(TI, h *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() {
		return false
	}
	ec := tss.EC()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{
		cHash := common.SHA512_256i(
			TI.X(), TI.Y(), h.X(), h.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	tG, uH := crypto.ScalarBaseMult(ec, pf.T), h.ScalarMult(pf.U)
	tGuH, _ := tG.Add(uH) // already on the curve.

	Tc := TI.ScalarMult(c)
	aTc, err := pf.Alpha.Add(Tc)
	if err != nil {
		return false
	}
	if tGuH.X().Cmp(aTc.X()) != 0 || tGuH.Y().Cmp(aTc.Y()) != 0 {
		return false
	}
	return true
}

func (pf *TProof) ValidateBasic() bool {
	return pf.Alpha != nil &&
		pf.T != nil && pf.U != nil &&
		pf.Alpha.ValidateBasic()
}

// ----- //

// NewSTProof constructs a new ZK proof of knowledge sigma_i, l_i such that S_i = R^sigma_i, T_i = g^sigma_i h^l_i (GG20)
func NewSTProof(TI, R, h *crypto.ECPoint, sigmaI, lI *big.Int) (*STProof, error) {
	if TI == nil || R == nil || h == nil || sigmaI == nil || lI == nil ||
		!TI.ValidateBasic() || !R.ValidateBasic() || !h.ValidateBasic() {
		return nil, errors.New("NewSTProof received nil or invalid value(s)")
	}
	ec := tss.EC()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	a, b := common.GetRandomPositiveInt(q), common.GetRandomPositiveInt(q)

	alpha, aG, bH := R.ScalarMult(a), crypto.ScalarBaseMult(ec, a), h.ScalarMult(b)
	beta, _ := aG.Add(bH) // already on the curve.

	var c *big.Int
	{
		cHash := common.SHA512_256i(
			TI.X(), TI.Y(), h.X(), h.Y(), g.X(), g.Y(), alpha.X(), alpha.Y(), beta.X(), beta.Y())
		c = common.RejectionSample(q, cHash)
	}
	t, u := calculateTAndU(q, a, c, sigmaI, b, lI)
	return &STProof{Alpha: alpha, Beta: beta, T: t, U: u}, nil
}

func (pf *STProof) Verify(SI, TI, R, h *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() {
		return false
	}
	ec := tss.EC()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{
		cHash := common.SHA512_256i(
			TI.X(), TI.Y(), h.X(), h.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y(), pf.Beta.X(), pf.Beta.Y())
		c = common.RejectionSample(q, cHash)
	}
	tR, cS := R.ScalarMult(pf.T), SI.ScalarMult(c)
	aSc, err := pf.Alpha.Add(cS)
	if err != nil {
		return false
	}
	if tR.X().Cmp(aSc.X()) != 0 || tR.Y().Cmp(aSc.Y()) != 0 {
		return false
	}

	tG, uH, cT := crypto.ScalarBaseMult(ec, pf.T), h.ScalarMult(pf.U), TI.ScalarMult(c)
	tGuH, _ := tG.Add(uH) // already on the curve.
	bTc, err := pf.Beta.Add(cT)
	if err != nil {
		return false
	}
	if tGuH.X().Cmp(bTc.X()) != 0 || tGuH.Y().Cmp(bTc.Y()) != 0 {
		return false
	}
	return true
}

func (pf *STProof) ValidateBasic() bool {
	return pf.Alpha != nil && pf.Beta != nil &&
		pf.T != nil && pf.U != nil &&
		pf.Alpha.ValidateBasic() &&
		pf.Beta.ValidateBasic()
}

// ----- //

func calculateTAndU(q, a, c, sigmaI, b, lI *big.Int) (t, u *big.Int) {
	modQ := common.ModInt(q)
	t = modQ.Add(a, new(big.Int).Mul(c, sigmaI))
	u = modQ.Add(b, new(big.Int).Mul(c, lI))
	return
}
