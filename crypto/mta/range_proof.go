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

func ProveRangeAlice(pk *paillier.PublicKey, c, NTilde, h1, h2, m, r *big.Int) *RangeProofAlice {
	q := tss.EC().Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)

	alpha := random.GetRandomPositiveInt(q3)

	beta := random.GetRandomPositiveRelativelyPrimeInt(pk.N)

	q3N := new(big.Int).Mul(q3, NTilde)
	gamma := random.GetRandomPositiveInt(q3N)

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
