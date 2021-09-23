// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpdec

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
)

const (
    ProofDecBytesParts = 7
)

type (
    ProofDec struct {
        S, T, A, Gamma, Z1, Z2, W *big.Int
    }
)

// NewProof implements proofenc
func NewProof(ec elliptic.Curve, pk *paillier.PublicKey, C, x, NCap, s, t, y, rho *big.Int) (*ProofDec, error) {
    if ec == nil || pk == nil || C == nil || x == nil || NCap == nil || s == nil || t == nil || y == nil || rho == nil {
        return nil, errors.New("ProveDec constructor received nil value(s)")
    }

    q := ec.Params().N
    q3 := new(big.Int).Mul(q, q)
    q3 = new(big.Int).Mul(q, q3)
    qNCap := new(big.Int).Mul(q, NCap)
    q3NCap := new(big.Int).Mul(q3, NCap)

    // Fig 29.1 sample
    alpha := common.GetRandomPositiveInt(q3)
    mu := common.GetRandomPositiveInt(qNCap)
	v := common.GetRandomPositiveInt(q3NCap)
    r := common.GetRandomPositiveRelativelyPrimeInt(pk.N)

    // Fig 29.1 compute
    modNCap := common.ModInt(NCap)
    S := modNCap.Exp(s, y)
    S = modNCap.Mul(S, modNCap.Exp(t, mu))

	T := modNCap.Exp(s, alpha)
    T = modNCap.Mul(T, modNCap.Exp(t, v))


    modNSquared := common.ModInt(pk.NSquare())
    A := modNSquared.Exp(pk.Gamma(), alpha)
    A = modNSquared.Mul(A, modNSquared.Exp(r, pk.N))

    gamma := new(big.Int).Mod(alpha, q)

    // Fig 29.2 e
    var e *big.Int
    {
        eHash := common.SHA512_256i(append(pk.AsInts(), C, x, NCap, s, t, A, gamma)...)
        e = common.RejectionSample(q, eHash)
    }

    // Fig 14.3
    z1 := new(big.Int).Mul(e, y)
    z1 = new(big.Int).Add(alpha, z1)
    
    z2 := new(big.Int).Mul(e, mu)
    z2 = new(big.Int).Add(v, z2)

	modN := common.ModInt(pk.N)
    w := modN.Exp(rho, e)
    w = modN.Mul(r, w)

    return &ProofDec{S: S, T: T, A: A, Gamma: gamma, Z1: z1, Z2: z2, W: w}, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofDec, error) {
    if !common.NonEmptyMultiBytes(bzs, ProofDecBytesParts) {
        return nil, fmt.Errorf("expected %d byte parts to construct ProofDec", ProofDecBytesParts)
    }
    return &ProofDec{
        S:     new(big.Int).SetBytes(bzs[0]),
		T:     new(big.Int).SetBytes(bzs[1]),
        A:     new(big.Int).SetBytes(bzs[2]),
        Gamma: new(big.Int).SetBytes(bzs[3]),
        Z1:    new(big.Int).SetBytes(bzs[4]),
        Z2:    new(big.Int).SetBytes(bzs[5]),
        W:     new(big.Int).SetBytes(bzs[6]),
    }, nil
}

func (pf *ProofDec) Verify(ec elliptic.Curve, pk *paillier.PublicKey, C, x, NCap, s, t *big.Int) bool {
    if pf == nil || !pf.ValidateBasic() || ec == nil || pk == nil || C == nil || x == nil || NCap == nil || s == nil || t == nil {
        return false
    }

    q := ec.Params().N
    // q3 := new(big.Int).Mul(q, q)
    // q3 = new(big.Int).Mul(q, q3)

    var e *big.Int
    {
        eHash := common.SHA512_256i(append(pk.AsInts(), C, x, NCap, s, t, pf.A, pf.Gamma)...)
        e = common.RejectionSample(q, eHash)
    }

    // Fig 29. Equality Check
	{
		modNSquare := common.ModInt(pk.NSquare())
		Np1EXPz1 := modNSquare.Exp(pk.Gamma(), pf.Z1)
		wEXPN := modNSquare.Exp(pf.W, pk.N)
		left := modNSquare.Mul(Np1EXPz1, wEXPN)

		CEXPe := modNSquare.Exp(C, e)
		right := modNSquare.Mul(pf.A, CEXPe)

		if left.Cmp(right) != 0 {
			return false
		}
	}

	{
		modQ := common.ModInt(q)
		left := new(big.Int).Mod(pf.Z1, q)
		right := modQ.Add(modQ.Mul(e, x), pf.Gamma)

		if left.Cmp(right) != 0 {
			return false
		}
	}

    {
        modNCap := common.ModInt(NCap)
        sEXPz1 := modNCap.Exp(s, pf.Z1)
        tEXPz2 := modNCap.Exp(t, pf.Z2)
        left := modNCap.Mul(sEXPz1, tEXPz2)

        SEXPe := modNCap.Exp(pf.S, e)
        right := modNCap.Mul(pf.T, SEXPe)

        if left.Cmp(right) != 0 {
            return false
        }
    }
    return true
}

func (pf *ProofDec) ValidateBasic() bool {
    return pf.S != nil &&
		pf.T != nil &&
        pf.A != nil &&
        pf.Gamma != nil &&
        pf.Z1 != nil &&
        pf.Z2 != nil &&
        pf.W != nil
}

func (pf *ProofDec) Bytes() [ProofDecBytesParts][]byte {
    return [...][]byte{
        pf.S.Bytes(),
		pf.T.Bytes(),
        pf.A.Bytes(),
        pf.Gamma.Bytes(),
        pf.Z1.Bytes(),
        pf.Z2.Bytes(),
        pf.W.Bytes(),
    }
}
