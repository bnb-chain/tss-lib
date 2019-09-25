package mta

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	RangeProofAliceBytesParts = 6
)

var (
	zero = big.NewInt(0)
)

type (
	RangeProofAlice struct {
		Z, U, W, S, S1, S2 *big.Int
	}
)

// ProveRangeAlice implements Alice's range proof used in the MtA and MtAwc protocols from GG18Spec (9) Fig. 9.
func ProveRangeAlice(pk *paillier.PublicKey, c, NTilde, h1, h2, m, r *big.Int) (*RangeProofAlice, error) {
	if pk == nil || NTilde == nil || h1 == nil || h2 == nil || c == nil || m == nil || r == nil {
		return nil, errors.New("ProveRangeAlice constructor received nil value(s)")
	}

	q := tss.EC().Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	qNTilde := new(big.Int).Mul(q, NTilde)
	q3NTilde := new(big.Int).Mul(q3, NTilde)

	// 1.
	alpha := common.GetRandomPositiveInt(q3)
	// 2.
	beta := common.GetRandomPositiveRelativelyPrimeInt(pk.N)

	// 3.
	gamma := common.GetRandomPositiveInt(q3NTilde)

	// 4.
	rho := common.GetRandomPositiveInt(qNTilde)

	// 5.
	modNTilde := common.ModInt(NTilde)
	z := modNTilde.Exp(h1, m)
	z = modNTilde.Mul(z, modNTilde.Exp(h2, rho))

	// 6.
	modNSquared := common.ModInt(pk.NSquare())
	u := modNSquared.Exp(pk.Gamma(), alpha)
	u = modNSquared.Mul(u, modNSquared.Exp(beta, pk.N))

	// 7.
	w := modNTilde.Exp(h1, alpha)
	w = modNTilde.Mul(w, modNTilde.Exp(h2, gamma))

	// 8-9. e'
	var e *big.Int
	{ // must use RejectionSample
		eHash := common.SHA512_256i(append(pk.AsInts(), c, z, u, w)...)
		e = common.RejectionSample(q, eHash)
	}

	modN := common.ModInt(pk.N)
	s := modN.Exp(r, e)
	s = modN.Mul(s, beta)

	// s1 = e * m + alpha
	s1 := new(big.Int).Mul(e, m)
	s1 = new(big.Int).Add(s1, alpha)

	// s2 = e * rho + gamma
	s2 := new(big.Int).Mul(e, rho)
	s2 = new(big.Int).Add(s2, gamma)

	return &RangeProofAlice{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}, nil
}

func RangeProofAliceFromBytes(bzs [][]byte) (*RangeProofAlice, error) {
	if !common.NonEmptyMultiBytes(bzs, RangeProofAliceBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct RangeProofAlice", RangeProofAliceBytesParts)
	}
	return &RangeProofAlice{
		Z:  new(big.Int).SetBytes(bzs[0]),
		U:  new(big.Int).SetBytes(bzs[1]),
		W:  new(big.Int).SetBytes(bzs[2]),
		S:  new(big.Int).SetBytes(bzs[3]),
		S1: new(big.Int).SetBytes(bzs[4]),
		S2: new(big.Int).SetBytes(bzs[5]),
	}, nil
}

func (pf *RangeProofAlice) Verify(pk *paillier.PublicKey, NTilde, h1, h2, c *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() || pk == nil || NTilde == nil || h1 == nil || h2 == nil || c == nil {
		return false
	}

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
		eHash := common.SHA512_256i(append(pk.AsInts(), c, pf.Z, pf.U, pf.W)...)
		e = common.RejectionSample(q, eHash)
	}

	var products *big.Int // for the following conditionals
	minusE := new(big.Int).Sub(zero, e)

	{ // 4. gamma^s_1 * s^N * c^-e
		modN2 := common.ModInt(N2)

		cExpMinusE := modN2.Exp(c, minusE)
		sExpN := modN2.Exp(pf.S, pk.N)
		gammaExpS1 := modN2.Exp(pk.Gamma(), pf.S1)
		// u != (4)
		products = modN2.Mul(gammaExpS1, sExpN)
		products = modN2.Mul(products, cExpMinusE)
		if pf.U.Cmp(products) != 0 {
			return false
		}
	}

	{ // 5. h_1^s_1 * h_2^s_2 * z^-e
		modNTilde := common.ModInt(NTilde)

		h1ExpS1 := modNTilde.Exp(h1, pf.S1)
		h2ExpS2 := modNTilde.Exp(h2, pf.S2)
		zExpMinusE := modNTilde.Exp(pf.Z, minusE)
		// w != (5)
		products = modNTilde.Mul(h1ExpS1, h2ExpS2)
		products = modNTilde.Mul(products, zExpMinusE)
		if pf.W.Cmp(products) != 0 {
			return false
		}
	}
	return true
}

func (pf *RangeProofAlice) ValidateBasic() bool {
	return pf.Z != nil &&
		pf.U != nil &&
		pf.W != nil &&
		pf.S != nil &&
		pf.S1 != nil &&
		pf.S2 != nil
}

func (pf *RangeProofAlice) Bytes() [RangeProofAliceBytesParts][]byte {
	return [...][]byte{
		pf.Z.Bytes(),
		pf.U.Bytes(),
		pf.W.Bytes(),
		pf.S.Bytes(),
		pf.S1.Bytes(),
		pf.S2.Bytes(),
	}
}
