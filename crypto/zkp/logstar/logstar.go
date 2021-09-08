// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkplogstar

import (
    "crypto/elliptic"
    "errors"
    "fmt"
    "math/big"

    "github.com/binance-chain/tss-lib/common"
    "github.com/binance-chain/tss-lib/crypto"
    "github.com/binance-chain/tss-lib/crypto/paillier"
)

const (
    ProofLogstarBytesParts = 8
)

type (
    ProofLogstar struct {
        S, A *big.Int
        Y *crypto.ECPoint 
        D, Z1, Z2, Z3 *big.Int
    }
)

// NewProof implements prooflogstar
func NewProof(ec elliptic.Curve, pk *paillier.PublicKey, C *big.Int, X *crypto.ECPoint, g *crypto.ECPoint, NCap, s, t, x, rho *big.Int) (*ProofLogstar, error) {
    if ec == nil || pk == nil || C == nil || X == nil || g == nil || NCap == nil || s == nil || t == nil || x == nil || rho == nil {
        return nil, errors.New("ProveLogstar constructor received nil value(s)")
    }

    q := ec.Params().N
    q3 := new(big.Int).Mul(q, q)
    q3 = new(big.Int).Mul(q, q3)
    qNCap := new(big.Int).Mul(q, NCap)
    q3NCap := new(big.Int).Mul(q3, NCap)

    // Fig 25.1 sample
    alpha := common.GetRandomPositiveInt(q3)
    mu := common.GetRandomPositiveInt(qNCap)
    r := common.GetRandomPositiveRelativelyPrimeInt(pk.N)
    gamma := common.GetRandomPositiveInt(q3NCap)	

    // Fig 25.1 compute
    modNCap := common.ModInt(NCap)
    S := modNCap.Exp(s, x)
    S = modNCap.Mul(S, modNCap.Exp(t, mu))

    modNSquared := common.ModInt(pk.NSquare())
    A := modNSquared.Exp(pk.Gamma(), alpha)
    A = modNSquared.Mul(A, modNSquared.Exp(r, pk.N))

    // Y := crypto.ScalarBaseMult(ec, alpha)
	Y := g.ScalarMult(alpha)

    D := modNCap.Exp(s, alpha)
    D = modNCap.Mul(D, modNCap.Exp(t, gamma))

    // Fig 25.2 e
    var e *big.Int
    {
        eHash := common.SHA512_256i(append(pk.AsInts(), S, Y.X(), Y.Y(), A, D)...)
        e = common.RejectionSample(q, eHash)
    }

    // Fig 25.3
    z1 := new(big.Int).Mul(e, x)
    z1 = new(big.Int).Add(z1, alpha)

    modN := common.ModInt(pk.N)
    z2 := modN.Exp(rho, e)
    z2 = modN.Mul(z2, r)

    z3 := new(big.Int).Mul(e, mu)
    z3 = new(big.Int).Add(z3, gamma)

    return &ProofLogstar{S: S, A: A, Y: Y, D: D, Z1: z1, Z2: z2, Z3: z3}, nil
}

func NewProofFromBytes(ec elliptic.Curve, bzs [][]byte) (*ProofLogstar, error) {
    if !common.NonEmptyMultiBytes(bzs, ProofLogstarBytesParts) {
        return nil, fmt.Errorf("expected %d byte parts to construct ProofLogstar", ProofLogstarBytesParts)
    }
    point, err := crypto.NewECPoint(ec,
        new(big.Int).SetBytes(bzs[2]),
        new(big.Int).SetBytes(bzs[3]))
    if err != nil {
        return nil, err
    }
    return &ProofLogstar{
        S:  new(big.Int).SetBytes(bzs[0]),
        A:  new(big.Int).SetBytes(bzs[1]),
        Y:  point,
        D:  new(big.Int).SetBytes(bzs[4]),
        Z1: new(big.Int).SetBytes(bzs[5]),
        Z2: new(big.Int).SetBytes(bzs[6]),
        Z3: new(big.Int).SetBytes(bzs[7]),
    }, nil
}

func (pf *ProofLogstar) Verify(ec elliptic.Curve, pk *paillier.PublicKey, C *big.Int, X *crypto.ECPoint, g *crypto.ECPoint, NCap, s, t *big.Int) bool {
    if pf == nil || !pf.ValidateBasic() || ec == nil || pk == nil || C == nil || X == nil || NCap == nil || s == nil || t == nil {
        return false
    }

    q := ec.Params().N
    q3 := new(big.Int).Mul(q, q)
    q3 = new(big.Int).Mul(q, q3)

    // Fig 25. range check
    if pf.Z1.Cmp(q3) == 1 {
        return false
    }

    var e *big.Int
    {
        eHash := common.SHA512_256i(append(pk.AsInts(), pf.S, pf.Y.X(), pf.Y.Y(), pf.A, pf.D)...)
        e = common.RejectionSample(q, eHash)
    }

    // Fig 25. equality checks
    {
        modNSquared := common.ModInt(pk.NSquare())

        Np1EXPz1 := modNSquared.Exp(pk.Gamma(), pf.Z1)
        z2EXPN := modNSquared.Exp(pf.Z2, pk.N)
        left := modNSquared.Mul(Np1EXPz1, z2EXPN)

        CEXPe := modNSquared.Exp(C, e)
        right := modNSquared.Mul(CEXPe, pf.A)
        if left.Cmp(right) != 0 {
            return false
        }
    }

    {
        z1ModQ := new(big.Int).Mod(pf.Z1, ec.Params().N)
        // left := crypto.ScalarBaseMult(ec, z1ModQ)
        left := g.ScalarMult(z1ModQ)
        right, err := X.ScalarMult(e).Add(pf.Y)
        if err != nil || !left.Equals(right) {
            return false
        }
    }

    {
        modNCap := common.ModInt(NCap)
        sEXPz1 := modNCap.Exp(s, pf.Z1)
        tEXPz3 := modNCap.Exp(t, pf.Z3)
        left := modNCap.Mul(sEXPz1, tEXPz3)
        SEXPe := modNCap.Exp(pf.S, e)
        right := modNCap.Mul(pf.D, SEXPe)
        if left.Cmp(right) != 0 {
            return false
        }
    }
    return true
}

func (pf *ProofLogstar) ValidateBasic() bool {
    return pf.S != nil &&
        pf.A != nil &&
        pf.Y != nil &&
        pf.D != nil &&
        pf.Z1 != nil &&
        pf.Z2 != nil &&
        pf.Z3 != nil
}

func (pf *ProofLogstar) Bytes() [ProofLogstarBytesParts][]byte {
    return [...][]byte{
        pf.S.Bytes(),
        pf.A.Bytes(),
        pf.Y.X().Bytes(),
        pf.Y.Y().Bytes(),
        pf.D.Bytes(),
        pf.Z1.Bytes(),
        pf.Z2.Bytes(),
        pf.Z3.Bytes(),
    }
}
