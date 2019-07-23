package schnorr

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
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

// NewZKProof constructs a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func NewZKProof(x *big.Int, X *crypto.ECPoint) *ZKProof {
	ecParams := tss.EC().Params()
	q := ecParams.N
	g := crypto.NewECPoint(tss.EC(), ecParams.Gx, ecParams.Gy)

	a := random.GetRandomPositiveInt(q)
	alpha := crypto.ScalarBaseMult(tss.EC(), a)

	var c *big.Int
	{ // must use RejectionSample
		cHash := common.SHA512_256i(X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	t := new(big.Int).Mul(c, x)
	t = common.ModInt(q).Add(a, t)

	return &ZKProof{Alpha: alpha, T: t}
}

// NewZKProof verifies a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func (pf *ZKProof) Verify(X *crypto.ECPoint) bool {
	ecParams := tss.EC().Params()
	q := ecParams.N
	g := crypto.NewECPoint(tss.EC(), ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{ // must use RejectionSample
		cHash := common.SHA512_256i(X.X(), X.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	tG := crypto.ScalarBaseMult(tss.EC(), pf.T)
	Xc := X.ScalarMult(c)
	aXc := pf.Alpha.Add(Xc)

	if aXc.X().Cmp(tG.X()) != 0 || aXc.Y().Cmp(tG.Y()) != 0 {
		return false
	}
	return true
}

func (pf *ZKProof) ValidateBasic() bool {
	return pf.T != nil && pf.Alpha != nil
}

// NewZKProof constructs a new Schnorr ZK proof of knowledge s_i, l_i such that V_i = R^s_i, g^l_i (GG18Spec Fig. 17)
func NewZKVProof(V, R *crypto.ECPoint, s, l *big.Int) *ZKVProof {
	ecParams := tss.EC().Params()
	q := ecParams.N
	g := crypto.NewECPoint(tss.EC(), ecParams.Gx, ecParams.Gy)

	a, b := random.GetRandomPositiveInt(q), random.GetRandomPositiveInt(q)
	aR := R.ScalarMult(a)
	bG := crypto.ScalarBaseMult(tss.EC(), b)
	alpha := aR.Add(bG)

	var c *big.Int
	{ // must use RejectionSample
		cHash := common.SHA512_256i(V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	modQ := common.ModInt(q)
	t := modQ.Add(a, new(big.Int).Mul(c, s))
	u := modQ.Add(b, new(big.Int).Mul(c, l))

	return &ZKVProof{Alpha: alpha, T: t, U: u}
}

func (pf *ZKVProof) Verify(V, R *crypto.ECPoint) bool {
	ecParams := tss.EC().Params()
	q := ecParams.N
	g := crypto.NewECPoint(tss.EC(), ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{ // must use RejectionSample
		cHash := common.SHA512_256i(V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	tR := R.ScalarMult(pf.T)
	uG := crypto.ScalarBaseMult(tss.EC(), pf.U)
	tRuG := tR.Add(uG)

	Vc := V.ScalarMult(c)
	aVc := pf.Alpha.Add(Vc)

	if tRuG.X().Cmp(aVc.X()) != 0 || tRuG.Y().Cmp(aVc.Y()) != 0 {
		return false
	}
	return true
}

func (pf *ZKVProof) ValidateBasic() bool {
	return pf.Alpha != nil && pf.T != nil && pf.U != nil
}
