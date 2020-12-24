package zkp

import (
	"crypto/elliptic"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
)

type (
	ECDDHStatement struct {
		Curve elliptic.Curve
		G2,
		H1, H2 *crypto.ECPoint
	}

	ECDDHWitness struct {
		X *big.Int
	}

	ECDDHProof struct {
		A1, A2 *crypto.ECPoint
		Z      *big.Int
	}
)

func NewECSigmaIProof(curve elliptic.Curve, sigmaI *big.Int, R, SI *crypto.ECPoint) (*ECDDHProof, error) {
	// TODO: pull in R as an argument?
	st := ECDDHStatement{
		Curve: curve,
		G2:    R,
		H1:    crypto.ScalarBaseMult(curve, sigmaI),
		H2:    SI,
	}
	wit := ECDDHWitness{X: sigmaI}
	pf := NewECDDHProof(wit, st)
	return &pf, nil
}

func NewECDDHProof(wit ECDDHWitness, st ECDDHStatement) ECDDHProof {
	g1 := crypto.NewECPointNoCurveCheck(st.Curve, st.Curve.Params().Gx, st.Curve.Params().Gy)
	s := common.GetRandomPositiveInt(st.Curve.Params().N)
	a1 := crypto.ScalarBaseMult(st.Curve, s)
	a2 := st.G2.ScalarMult(s)
	e := common.SHA512_256(g1.Bytes(), st.H1.Bytes(), st.G2.Bytes(), st.H2.Bytes(), a1.Bytes(), a2.Bytes())
	eWX := new(big.Int).SetBytes(e)
	eWX.Mul(eWX, wit.X)
	return ECDDHProof{
		A1: a1,
		A2: a2,
		Z:  s.Add(s, eWX),
	}
}

func (pf *ECDDHProof) Verify(st ECDDHStatement) bool {
	g1 := crypto.NewECPointNoCurveCheck(st.Curve, st.Curve.Params().Gx, st.Curve.Params().Gy)
	zG1, zG2 := g1.ScalarMult(pf.Z), st.G2.ScalarMult(pf.Z)
	e := common.SHA512_256(g1.Bytes(), st.H1.Bytes(), st.G2.Bytes(), st.H2.Bytes(), pf.A1.Bytes(), pf.A2.Bytes())
	eInt := new(big.Int).SetBytes(e)
	if a1PlusEH1, err := st.H1.ScalarMult(eInt).Add(pf.A1); err == nil {
		if a2PlusEH2, err := st.H2.ScalarMult(eInt).Add(pf.A2); err == nil {
			return zG1.Equals(a1PlusEH1) && zG2.Equals(a2PlusEH2)
		}
	}
	return false
}

func (pf *ECDDHProof) VerifySigmaI(curve elliptic.Curve, gSigmaI, R, SI *crypto.ECPoint) bool {
	st := ECDDHStatement{
		Curve: curve,
		G2:    R,
		H1:    gSigmaI,
		H2:    SI,
	}
	return pf.Verify(st)
}
