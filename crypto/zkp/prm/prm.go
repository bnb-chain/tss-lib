// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpprm

import (
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
)

const (
	Iterations = 64
    ProofPrmBytesParts = Iterations*2
)

type (
	ProofPrm struct {
		A [Iterations]*big.Int
		Z [Iterations]*big.Int
	}
)

func NewProof(s, t, N, Phi, lambda *big.Int) (*ProofPrm, error) {
	modN, modPhi := common.ModInt(N), common.ModInt(Phi)

	// Fig 17.1
	a := make([]*big.Int, Iterations)
	A := [Iterations]*big.Int{}
	for i := range A {
		a[i] = common.GetRandomPositiveInt(Phi)
		A[i] = modN.Exp(t, a[i])
	}

	// Fig 17.2
	e := common.SHA512_256i(append([]*big.Int{s, t, N}, A[:]...)...)
	
	// Fig 17.3
	Z := [Iterations]*big.Int{}
	for i := range Z {
		ei := big.NewInt(int64(e.Bit(i)))
		Z[i] = modPhi.Add(a[i], modPhi.Mul(ei, lambda))
	}
	return &ProofPrm{A: A, Z: Z}, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofPrm, error) {
    if !common.NonEmptyMultiBytes(bzs, ProofPrmBytesParts) {
        return nil, fmt.Errorf("expected %d byte parts to construct ProofPrm", ProofPrmBytesParts)
    }
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}
	A := [Iterations]*big.Int{}
	copy(A[:], bis[:Iterations])

	Z := [Iterations]*big.Int{}
	copy(Z[:], bis[Iterations:])

    return &ProofPrm{
        A: A,
        Z: Z,
    }, nil
}

func (pf *ProofPrm) Verify(s, t, N *big.Int) bool {
	if pf == nil  || !pf.ValidateBasic() {
		return false
	}
	modN := common.ModInt(N)
	e := common.SHA512_256i(append([]*big.Int{s, t, N}, pf.A[:]...)...)

	// Fig 17. Verification
	for i := 0; i < Iterations; i++ {
		ei := big.NewInt(int64(e.Bit(i)))
		left := modN.Exp(t, pf.Z[i])
		right := modN.Exp(s, ei)
		right = modN.Mul(pf.A[i], right)
		if left.Cmp(right) != 0 {
			return false
		}
	}
	return true
}

func (pf *ProofPrm) ValidateBasic() bool {
    for i := range pf.A {
		if pf.A[i] == nil {
			return false
		}
	}
	for i := range pf.Z {
		if pf.Z[i] == nil {
			return false
		}
	}
	return true
}

func (pf *ProofPrm) Bytes() [ProofPrmBytesParts][]byte {
    bzs := [ProofPrmBytesParts][]byte{}
	for i := range pf.A {
		bzs[i] = pf.A[i].Bytes()
	}
	for i := range pf.Z {
		bzs[i+Iterations] = pf.Z[i].Bytes()
	}
	return bzs
}
