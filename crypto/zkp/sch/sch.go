// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpsch

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
)

const (
    ProofSchBytesParts = 3
)

type (
	ProofSch struct {
		A *crypto.ECPoint
		Z *big.Int
	}
)

// NewProof implements proofsch
func NewProof(X *crypto.ECPoint, x *big.Int) (*ProofSch, error) {
	if x == nil || X == nil || !X.ValidateBasic() {
		return nil, errors.New("zkpsch constructor received nil or invalid value(s)")
	}
	ec := X.Curve()
	q := ec.Params().N
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy) // already on the curve.

	// Fig 22.1
	alpha := common.GetRandomPositiveInt(q)
	A := crypto.ScalarBaseMult(ec, alpha)

	// Fig 22.2 e
	var e *big.Int
	{
		eHash := common.SHA512_256i(X.X(), X.Y(), g.X(), g.Y(), A.X(), A.Y())
		e = common.RejectionSample(q, eHash)
	}

	// Fig 22.3
	z := new(big.Int).Mul(e, x)
	z = common.ModInt(q).Add(alpha, z)

	return &ProofSch{A: A, Z: z}, nil
}

func NewProofFromBytes(ec elliptic.Curve, bzs [][]byte) (*ProofSch, error) {
    if !common.NonEmptyMultiBytes(bzs, ProofSchBytesParts) {
        return nil, fmt.Errorf("expected %d byte parts to construct ProofSch", ProofSchBytesParts)
    }
	point, err := crypto.NewECPoint(ec,
        new(big.Int).SetBytes(bzs[0]),
        new(big.Int).SetBytes(bzs[1]))
    if err != nil {
        return nil, err
    }
    return &ProofSch{
        A: point,
        Z: new(big.Int).SetBytes(bzs[2]),
    }, nil
}

func (pf *ProofSch) Verify(X *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() || X == nil {
		return false
	}
	ec := X.Curve()
	q := ec.Params().N
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)

	var e *big.Int
	{
		eHash := common.SHA512_256i(X.X(), X.Y(), g.X(), g.Y(), pf.A.X(), pf.A.Y())
		e = common.RejectionSample(q, eHash)
	}

	// Fig 22. Verification
	left := crypto.ScalarBaseMult(ec, pf.Z)
	XEXPe := X.ScalarMult(e)
	right, err := pf.A.Add(XEXPe)
	if err != nil {
		return false
	}
	if right.X().Cmp(left.X()) != 0 || right.Y().Cmp(left.Y()) != 0 {
		return false
	}
	return true
}

func (pf *ProofSch) ValidateBasic() bool {
	return pf.Z != nil && pf.A != nil
}

func (pf *ProofSch) Bytes() [ProofSchBytesParts][]byte {
    return [...][]byte{
        pf.A.X().Bytes(),
        pf.A.Y().Bytes(),
        pf.Z.Bytes(),
    }
}
