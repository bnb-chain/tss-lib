package schnorr

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

type SchnorrProof struct {
	Alpha *crypto.ECPoint
	T     *big.Int
}

// NewSchnorrProof can throw an error if writing the SHA3 hash fails
func NewSchnorrProof(x *big.Int, X *crypto.ECPoint) (*SchnorrProof, error) {
	ecParams := tss.EC().Params()
	q := ecParams.N
	g := crypto.NewECPoint(ecParams.Gx, ecParams.Gy)
	a := random.GetRandomPositiveInt(q)
	alpha := crypto.ScalarBaseMult(tss.EC(), a)

	cHash, err := common.SHA3_256i(X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
	if err != nil {
		return nil, err
	}
	c, err := common.RejectionSample(q, cHash)
	if err != nil {
		return nil, err
	}

	t := new(big.Int).Mul(c, x)
	t = new(big.Int).Add(a, t)
	t = new(big.Int).Mod(t, q)

	return &SchnorrProof{Alpha: alpha, T: t}, nil
}

// Verify can throw an error if writing the SHA3 hash fails
func (pf *SchnorrProof) Verify(X *crypto.ECPoint) (bool, error) {
	ecParams := tss.EC().Params()
	q := ecParams.N
	g := crypto.NewECPoint(ecParams.Gx, ecParams.Gy)

	cHash, err := common.SHA3_256i(X.X(), X.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
	if err != nil {
		return false, err
	}
	c, err := common.RejectionSample(q, cHash)
	if err != nil {
		return false, err
	}

	tG := crypto.ScalarBaseMult(tss.EC(), pf.T)
	Xc := X.ScalarMult(tss.EC(), c)
	aXc := pf.Alpha.Add(tss.EC(), Xc)

	if aXc.X().Cmp(tG.X()) != 0 || aXc.Y().Cmp(tG.Y()) != 0 {
		return false, nil
	}
	return true, nil
}
