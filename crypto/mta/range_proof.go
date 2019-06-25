package mta

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

type RangeProofAlice struct {
	Z, U, W, S, S1, S2 *big.Int
}

type ProveMtaBob struct {
}

var (
	zero = big.NewInt(0)
)

func ProveRangeAlice(pk *paillier.PublicKey, c, NTilde, h1, h2, m, r *big.Int) *RangeProofAlice {
	q := tss.EC().Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)

	// 1.
	alpha := random.GetRandomPositiveInt(q3)
	// 2.
	beta := random.GetRandomPositiveRelativelyPrimeInt(pk.N)

	// 3.
	q3NTilde := new(big.Int).Mul(q3, NTilde)
	gamma := random.GetRandomPositiveInt(q3NTilde)

	// 4.
	qNTilde := new(big.Int).Mul(q, NTilde)
	rho := random.GetRandomPositiveInt(qNTilde)

	z := new(big.Int).Exp(h1, m, NTilde)
	z = new(big.Int).Mul(z, new(big.Int).Exp(h2, rho, NTilde))
	z = new(big.Int).Mod(z, NTilde)

	u := new(big.Int).Exp(pk.Gamma, alpha, pk.NSquare())
	u = new(big.Int).Mul(u, new(big.Int).Exp(beta, pk.N, pk.NSquare()))
	u = new(big.Int).Mod(u, pk.NSquare())

	w := new(big.Int).Exp(h1, alpha, NTilde)
	w = new(big.Int).Mul(w, new(big.Int).Exp(h2, gamma, NTilde))
	w = new(big.Int).Mod(w, NTilde)

	// e'
	var e *big.Int
	{ // must use RejectionSample
		eHash := common.SHA512_256i(pk.N, pk.Gamma, pk.PhiN, c, z, u, w)
		e = common.RejectionSample(q, eHash)
	}

	s := new(big.Int).Exp(r, e, pk.N)
	s = new(big.Int).Mul(s, beta)
	s = new(big.Int).Mod(s, pk.N)

	// s1 = e * m + alpha
	s1 := new(big.Int).Mul(e, m)
	s1 = new(big.Int).Add(s1, alpha)

	// s2 = e * rho + gamma
	s2 := new(big.Int).Mul(e, rho)
	s2 = new(big.Int).Add(s2, gamma)

	return &RangeProofAlice{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
}

func (pf *RangeProofAlice) Verify(pk *paillier.PublicKey, NTilde, h1, h2, c *big.Int) bool {
	N2 := new(big.Int).Mul(pk.N, pk.N)
	q := tss.EC().Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)

	// 3.
	if pf.S1.Cmp(q3) == 1 {
		return false
	}

	// 1-2. e'
	var e *big.Int
	{ // must use RejectionSample
		eHash := common.SHA512_256i(pk.N, pk.Gamma, pk.PhiN, c, pf.Z, pf.U, pf.W)
		e = common.RejectionSample(q, eHash)
	}

	// 4. gamma^s_1 * s^N * c^-e
	minusE := new(big.Int).Sub(zero, e)
	cExpMinusE := new(big.Int).Exp(c, minusE, N2)
	sExpN := new(big.Int).Exp(pf.S, pk.N, N2)
	gammaExpS1 := new(big.Int).Exp(pk.Gamma, pf.S1, N2)
	// u != (4)
	products := new(big.Int).Mul(gammaExpS1, sExpN)
	products = new(big.Int).Mul(products, cExpMinusE)
	if pf.U.Cmp(products) != 0 {
		return false
	}

	// 5. h_1^s_1 * h_2^s_2 * z^-e
	h1ExpS1 := new(big.Int).Exp(h1, pf.S1, NTilde)
	h2ExpS2 := new(big.Int).Exp(h2, pf.S2, NTilde)
	zExpMinusE := new(big.Int).Exp(pf.Z, minusE, NTilde)
	// w != (5)
	products = new(big.Int).Mul(h1ExpS1, h2ExpS2)
	products = new(big.Int).Mul(products, zExpMinusE)
	if pf.W.Cmp(products) != 0 {
		return false
	}
	return true
}
