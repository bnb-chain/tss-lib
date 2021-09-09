// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpenc

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
)

const (
    ProofEncBytesParts = 6
)

type (
    ProofEnc struct {
        S, A, C, Z1, Z2, Z3 *big.Int
    }
)

// NewProof implements proofenc
func NewProof(ec elliptic.Curve, pk *paillier.PublicKey, K, NCap, s, t, k, rho *big.Int) (*ProofEnc, error) {
    if ec == nil || pk == nil || K == nil || NCap == nil || s == nil || t == nil || k == nil || rho == nil {
        return nil, errors.New("ProveEnc constructor received nil value(s)")
    }

    q := ec.Params().N
    q3 := new(big.Int).Mul(q, q)
    q3 = new(big.Int).Mul(q, q3)
    qNCap := new(big.Int).Mul(q, NCap)
    q3NCap := new(big.Int).Mul(q3, NCap)

    // Fig 14.1 sample
    alpha := common.GetRandomPositiveInt(q3)
    mu := common.GetRandomPositiveInt(qNCap)
    r := common.GetRandomPositiveRelativelyPrimeInt(pk.N)
    gamma := common.GetRandomPositiveInt(q3NCap)

    // Fig 14.1 compute
    modNCap := common.ModInt(NCap)
    S := modNCap.Exp(s, k)
    S = modNCap.Mul(S, modNCap.Exp(t, mu))

    modNSquared := common.ModInt(pk.NSquare())
    A := modNSquared.Exp(pk.Gamma(), alpha)
    A = modNSquared.Mul(A, modNSquared.Exp(r, pk.N))

    C := modNCap.Exp(s, alpha)
    C = modNCap.Mul(C, modNCap.Exp(t, gamma))

    // Fig 14.2 e
    var e *big.Int
    {
        eHash := common.SHA512_256i(append(pk.AsInts(), K, S, A, C)...)
        e = common.RejectionSample(q, eHash)
    }

    // Fig 14.3
    z1 := new(big.Int).Mul(e, k)
    z1 = new(big.Int).Add(z1, alpha)

    modN := common.ModInt(pk.N)
    z2 := modN.Exp(rho, e)
    z2 = modN.Mul(z2, r)

    z3 := new(big.Int).Mul(e, mu)
    z3 = new(big.Int).Add(z3, gamma)

    return &ProofEnc{S: S, A: A, C: C, Z1: z1, Z2: z2, Z3: z3}, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofEnc, error) {
    if !common.NonEmptyMultiBytes(bzs, ProofEncBytesParts) {
        return nil, fmt.Errorf("expected %d byte parts to construct ProofEnc", ProofEncBytesParts)
    }
    return &ProofEnc{
        S:  new(big.Int).SetBytes(bzs[0]),
        A:  new(big.Int).SetBytes(bzs[1]),
        C:  new(big.Int).SetBytes(bzs[2]),
        Z1: new(big.Int).SetBytes(bzs[3]),
        Z2: new(big.Int).SetBytes(bzs[4]),
        Z3: new(big.Int).SetBytes(bzs[5]),
    }, nil
}

func (pf *ProofEnc) Verify(ec elliptic.Curve, pk *paillier.PublicKey, NCap, s, t, K *big.Int) bool {
    if pf == nil || !pf.ValidateBasic() || ec == nil || pk == nil || NCap == nil || s == nil || t == nil || K == nil {
        return false
    }

    q := ec.Params().N
    q3 := new(big.Int).Mul(q, q)
    q3 = new(big.Int).Mul(q, q3)

    // Fig 14. Range Check
    if pf.Z1.Cmp(q3) == 1 {
        return false
    }

    var e *big.Int
    {
        eHash := common.SHA512_256i(append(pk.AsInts(), K, pf.S, pf.A, pf.C)...)
        e = common.RejectionSample(q, eHash)
    }

    // Fig 14. Equality Check
    {
        modNSquare := common.ModInt(pk.NSquare())
        Np1EXPz1 := modNSquare.Exp(pk.Gamma(), pf.Z1)
        z2EXPN := modNSquare.Exp(pf.Z2, pk.N)
        left := modNSquare.Mul(Np1EXPz1, z2EXPN)

        KEXPe := modNSquare.Exp(K, e)
        right := modNSquare.Mul(pf.A, KEXPe)
        
        if left.Cmp(right) != 0 {
            return false
        }
    }

    {
        modNCap := common.ModInt(NCap)
        sEXPz1 := modNCap.Exp(s, pf.Z1)
        tEXPz3 := modNCap.Exp(t, pf.Z3)
        left := modNCap.Mul(sEXPz1, tEXPz3)

        SEXPe := modNCap.Exp(pf.S, e)
        right := modNCap.Mul(pf.C, SEXPe)
        if left.Cmp(right) != 0 {
            return false
        }
    }
    return true
}

func (pf *ProofEnc) ValidateBasic() bool {
    return pf.S != nil &&
        pf.A != nil &&
        pf.C != nil &&
        pf.Z1 != nil &&
        pf.Z2 != nil &&
        pf.Z3 != nil
}

func (pf *ProofEnc) Bytes() [ProofEncBytesParts][]byte {
    return [...][]byte{
        pf.S.Bytes(),
        pf.A.Bytes(),
        pf.C.Bytes(),
        pf.Z1.Bytes(),
        pf.Z2.Bytes(),
        pf.Z3.Bytes(),
    }
}
