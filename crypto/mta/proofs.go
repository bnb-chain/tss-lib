package mta

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

type ProofBob struct {
	Z, ZPrm, T, V, W, S, S1, S2, T1, T2 *big.Int
}

// ProveBob implements Bob's proof used in the MtA protocol from GG18Spec (9) Fig. 11.
func ProveBob(pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int) (*ProofBob, error) {
	if pk == nil || NTilde == nil || h1 == nil || h2 == nil || c1 == nil || c2 == nil || x == nil || y == nil || r == nil {
		return nil, errors.New("ProveBob() received a nil argument")
	}

	NSquared := pk.NSquare()

	q := tss.EC().Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	qNTilde := new(big.Int).Mul(q, NTilde)
	q3NTilde := new(big.Int).Mul(q3, NTilde)

	// 1.
	alpha := random.GetRandomPositiveInt(q3)

	// 2.
	rho := random.GetRandomPositiveInt(qNTilde)
	sigma := random.GetRandomPositiveInt(qNTilde)
	tau := random.GetRandomPositiveInt(qNTilde)

	// 3.
	rhoPrm := random.GetRandomPositiveInt(q3NTilde)

	// 4.
	beta := random.GetRandomPositiveRelativelyPrimeInt(pk.N)
	gamma := random.GetRandomPositiveRelativelyPrimeInt(pk.N)

	// 5.
	z := new(big.Int).Exp(h1, x, NTilde)
	z = new(big.Int).Mul(z, new(big.Int).Exp(h2, rho, NTilde))
	z = new(big.Int).Mod(z, NTilde)

	// 6.
	zPrm := new(big.Int).Exp(h1, alpha, NTilde)
	zPrm = new(big.Int).Mul(zPrm, new(big.Int).Exp(h2, rhoPrm, NTilde))
	zPrm = new(big.Int).Mod(zPrm, NTilde)

	// 7.
	t := new(big.Int).Exp(h1, y, NTilde)
	t = new(big.Int).Mul(t, new(big.Int).Exp(h2, sigma, NTilde))
	t = new(big.Int).Mod(t, NTilde)

	// 8.
	v := new(big.Int).Exp(c1, alpha, NSquared)
	v = new(big.Int).Mul(v, new(big.Int).Exp(pk.Gamma, gamma, NSquared))
	v = new(big.Int).Mul(v, new(big.Int).Exp(beta, pk.N, NSquared))
	v = new(big.Int).Mod(v, NSquared)

	// 9.
	w := new(big.Int).Exp(h1, gamma, NTilde)
	w = new(big.Int).Mul(w, new(big.Int).Exp(h2, tau, NTilde))
	w = new(big.Int).Mod(w, NTilde)

	// 10-11. e'
	var e *big.Int
	{ // must use RejectionSample
		eHash := common.SHA512_256i(append(pk.AsInts(), c1, c2, z, zPrm, t, v, w)...)
		e = common.RejectionSample(q, eHash)
	}

	// 12.
	s := new(big.Int).Exp(r, e, pk.N)
	s = new(big.Int).Mul(s, beta)
	s = new(big.Int).Mod(s, pk.N)

	// 13.
	s1 := new(big.Int).Mul(e, x)
	s1 = new(big.Int).Add(s1, alpha)

	// 14.
	s2 := new(big.Int).Mul(e, rho)
	s2 = new(big.Int).Add(s2, rhoPrm)

	// 15.
	t1 := new(big.Int).Mul(e, y)
	t1 = new(big.Int).Add(t1, gamma)

	// 16.
	t2 := new(big.Int).Mul(e, sigma)
	t2 = new(big.Int).Add(t2, tau)

	return &ProofBob{Z: z, ZPrm: zPrm, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}, nil
}

func (pf *ProofBob) Verify(pk *paillier.PublicKey, NTilde, h1, h2, c1, c2 *big.Int) bool {
	if pk == nil || NTilde == nil || h1 == nil || h2 == nil || c1 == nil || c2 == nil {
		return false
	}

	NSquared := pk.NSquare()

	q := tss.EC().Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)

	// 3.
	if pf.S1.Cmp(q3) > 0 {
		return false
	}

	// 1-2. e'
	var e *big.Int
	{ // must use RejectionSample
		eHash := common.SHA512_256i(append(pk.AsInts(), c1, c2, pf.Z, pf.ZPrm, pf.T, pf.V, pf.W)...)
		e = common.RejectionSample(q, eHash)
	}

	var left, right *big.Int // for the following conditionals

	{ // 4.
		h1ExpS1 := new(big.Int).Exp(h1, pf.S1, NTilde)
		h2ExpS2 := new(big.Int).Exp(h2, pf.S2, NTilde)
		left = new(big.Int).Mul(h1ExpS1, h2ExpS2)
		left = new(big.Int).Mod(left, NTilde)
		zExpE := new(big.Int).Exp(pf.Z, e, NTilde)
		right = new(big.Int).Mul(zExpE, pf.ZPrm)
		right = new(big.Int).Mod(right, NTilde)
		if left.Cmp(right) != 0 {
			return false
		}
	}

	{ // 5.
		h1ExpT1 := new(big.Int).Exp(h1, pf.T1, NTilde)
		h2ExpT2 := new(big.Int).Exp(h2, pf.T2, NTilde)
		left = new(big.Int).Mul(h1ExpT1, h2ExpT2)
		left = new(big.Int).Mod(left, NTilde)
		tExpE := new(big.Int).Exp(pf.T, e, NTilde)
		right = new(big.Int).Mul(tExpE, pf.W)
		right = new(big.Int).Mod(right, NTilde)
		if left.Cmp(right) != 0 {
			return false
		}
	}

	{ // 6.
		c1ExpS1 := new(big.Int).Exp(c1, pf.S1, NSquared)
		sExpN := new(big.Int).Exp(pf.S, pk.N, NSquared)
		gammaExpT1 := new(big.Int).Exp(pk.Gamma, pf.T1, NSquared)
		left = new(big.Int).Mul(c1ExpS1, sExpN)
		left = new(big.Int).Mul(left, gammaExpT1)
		left = new(big.Int).Mod(left, NSquared)
		c2ExpE := new(big.Int).Exp(c2, e, NSquared)
		right = new(big.Int).Mul(c2ExpE, pf.V)
		right = new(big.Int).Mod(right, NSquared)
		if left.Cmp(right) != 0 {
			return false
		}
	}
	return true
}
