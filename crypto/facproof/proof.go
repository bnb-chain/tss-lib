// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package facproof

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
)

const (
	ProofFacBytesParts = 11
)

type (
	ProofFac struct {
		P, Q, A, B, T, Sigma, Z1, Z2, W1, W2, V *big.Int
	}
)

var (
	// rangeParameter l limits the bits of p or q to be in [1024-l, 1024+l]
	rangeParameter = new(big.Int).Lsh(big.NewInt(1), 15)
	one            = big.NewInt(1)
)

// NewProof implements prooffac
func NewProof(Session []byte, ec elliptic.Curve, N0, NCap, s, t, N0p, N0q *big.Int, rand io.Reader) (*ProofFac, error) {
	if ec == nil || N0 == nil || NCap == nil || s == nil || t == nil || N0p == nil || N0q == nil {
		return nil, errors.New("ProveFac constructor received nil value(s)")
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	qNCap := new(big.Int).Mul(q, NCap)
	qN0NCap := new(big.Int).Mul(qNCap, N0)
	q3NCap := new(big.Int).Mul(q3, NCap)
	q3N0NCap := new(big.Int).Mul(q3NCap, N0)
	sqrtN0 := new(big.Int).Sqrt(N0)
	q3SqrtN0 := new(big.Int).Mul(q3, sqrtN0)

	// Fig 28.1 sample
	alpha := common.GetRandomPositiveInt(rand, q3SqrtN0)
	beta := common.GetRandomPositiveInt(rand, q3SqrtN0)
	mu := common.GetRandomPositiveInt(rand, qNCap)
	nu := common.GetRandomPositiveInt(rand, qNCap)
	sigma := common.GetRandomPositiveInt(rand, qN0NCap)
	r := common.GetRandomPositiveRelativelyPrimeInt(rand, q3N0NCap)
	x := common.GetRandomPositiveInt(rand, q3NCap)
	y := common.GetRandomPositiveInt(rand, q3NCap)

	// Fig 28.1 compute
	modNCap := common.ModInt(NCap)
	P := modNCap.Exp(s, N0p)
	P = modNCap.Mul(P, modNCap.Exp(t, mu))

	Q := modNCap.Exp(s, N0q)
	Q = modNCap.Mul(Q, modNCap.Exp(t, nu))

	A := modNCap.Exp(s, alpha)
	A = modNCap.Mul(A, modNCap.Exp(t, x))

	B := modNCap.Exp(s, beta)
	B = modNCap.Mul(B, modNCap.Exp(t, y))

	T := modNCap.Exp(Q, alpha)
	T = modNCap.Mul(T, modNCap.Exp(t, r))

	// Fig 28.2 e
	var e *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(Session, N0, NCap, s, t, P, Q, A, B, T, sigma)
		e = common.RejectionSample(q, eHash)
	}

	// Fig 28.3
	z1 := new(big.Int).Mul(e, N0p)
	z1 = new(big.Int).Add(z1, alpha)

	z2 := new(big.Int).Mul(e, N0q)
	z2 = new(big.Int).Add(z2, beta)

	w1 := new(big.Int).Mul(e, mu)
	w1 = new(big.Int).Add(w1, x)

	w2 := new(big.Int).Mul(e, nu)
	w2 = new(big.Int).Add(w2, y)

	v := new(big.Int).Mul(nu, N0p)
	v = new(big.Int).Sub(sigma, v)
	v = new(big.Int).Mul(e, v)
	v = new(big.Int).Add(v, r)

	return &ProofFac{P: P, Q: Q, A: A, B: B, T: T, Sigma: sigma, Z1: z1, Z2: z2, W1: w1, W2: w2, V: v}, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofFac, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofFacBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofFac", ProofFacBytesParts)
	}
	return &ProofFac{
		P:     new(big.Int).SetBytes(bzs[0]),
		Q:     new(big.Int).SetBytes(bzs[1]),
		A:     new(big.Int).SetBytes(bzs[2]),
		B:     new(big.Int).SetBytes(bzs[3]),
		T:     new(big.Int).SetBytes(bzs[4]),
		Sigma: new(big.Int).SetBytes(bzs[5]),
		Z1:    new(big.Int).SetBytes(bzs[6]),
		Z2:    new(big.Int).SetBytes(bzs[7]),
		W1:    new(big.Int).SetBytes(bzs[8]),
		W2:    new(big.Int).SetBytes(bzs[9]),
		V:     new(big.Int).SetBytes(bzs[10]),
	}, nil
}

func (pf *ProofFac) Verify(Session []byte, ec elliptic.Curve, N0, NCap, s, t *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() || ec == nil || N0 == nil || NCap == nil || s == nil || t == nil {
		return false
	}
	if N0.Sign() != 1 {
		return false
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	sqrtN0 := new(big.Int).Sqrt(N0)
	q3SqrtN0 := new(big.Int).Mul(q3, sqrtN0)

	// Fig 28. Range Check
	if !common.IsInInterval(pf.Z1, q3SqrtN0) {
		return false
	}

	if !common.IsInInterval(pf.Z2, q3SqrtN0) {
		return false
	}

	var e *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(Session, N0, NCap, s, t, pf.P, pf.Q, pf.A, pf.B, pf.T, pf.Sigma)
		e = common.RejectionSample(q, eHash)
	}

	// Fig 28. Equality Check
	modNCap := common.ModInt(NCap)
	{
		LHS := modNCap.Mul(modNCap.Exp(s, pf.Z1), modNCap.Exp(t, pf.W1))
		RHS := modNCap.Mul(pf.A, modNCap.Exp(pf.P, e))

		if LHS.Cmp(RHS) != 0 {
			return false
		}
	}

	{
		LHS := modNCap.Mul(modNCap.Exp(s, pf.Z2), modNCap.Exp(t, pf.W2))
		RHS := modNCap.Mul(pf.B, modNCap.Exp(pf.Q, e))

		if LHS.Cmp(RHS) != 0 {
			return false
		}
	}

	{
		R := modNCap.Mul(modNCap.Exp(s, N0), modNCap.Exp(t, pf.Sigma))
		LHS := modNCap.Mul(modNCap.Exp(pf.Q, pf.Z1), modNCap.Exp(t, pf.V))
		RHS := modNCap.Mul(pf.T, modNCap.Exp(R, e))

		if LHS.Cmp(RHS) != 0 {
			return false
		}
	}

	return true
}

func (pf *ProofFac) ValidateBasic() bool {
	return pf.P != nil &&
		pf.Q != nil &&
		pf.A != nil &&
		pf.B != nil &&
		pf.T != nil &&
		pf.Sigma != nil &&
		pf.Z1 != nil &&
		pf.Z2 != nil &&
		pf.W1 != nil &&
		pf.W2 != nil &&
		pf.V != nil
}

func (pf *ProofFac) Bytes() [ProofFacBytesParts][]byte {
	return [...][]byte{
		pf.P.Bytes(),
		pf.Q.Bytes(),
		pf.A.Bytes(),
		pf.B.Bytes(),
		pf.T.Bytes(),
		pf.Sigma.Bytes(),
		pf.Z1.Bytes(),
		pf.Z2.Bytes(),
		pf.W1.Bytes(),
		pf.W2.Bytes(),
		pf.V.Bytes(),
	}
}
