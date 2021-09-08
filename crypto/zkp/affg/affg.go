// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpaffg

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
    ProofAffgBytesParts = 14
)

type (
    ProofAffg struct {
        S, T, A *big.Int
        Bx *crypto.ECPoint
        By, E, F *big.Int
        Z1, Z2, Z3, Z4, W, Wy *big.Int
    }
)

// NewProof implements proofaff-g
func NewProof(ec elliptic.Curve, pk0 *paillier.PublicKey, pk1 *paillier.PublicKey, NCap, s, t, C, D, Y *big.Int, X *crypto.ECPoint, x, y, rho, rhoy *big.Int) (*ProofAffg, error) {
    if ec == nil || pk0 == nil || pk1 == nil || NCap == nil || s == nil || t == nil || C == nil || D == nil || Y == nil || X == nil || x == nil || y == nil || rho == nil || rhoy == nil {
        return nil, errors.New("ProveBob() received a nil argument")
    }

    NSquared := pk0.NSquare()

    q := ec.Params().N
    q3 := new(big.Int).Mul(q, q)
    q3 = new(big.Int).Mul(q, q3)
    q6 := new(big.Int).Mul(q3, q3)
    qNCap := new(big.Int).Mul(q, NCap)
    q3NCap := new(big.Int).Mul(q3, NCap)

    // Fig 15.1 sample
    alpha := common.GetRandomPositiveInt(q3)
    // beta := common.GetRandomPositiveRelativelyPrimeInt(pk0.N)
    beta := common.GetRandomPositiveRelativelyPrimeInt(q6)
    r := common.GetRandomPositiveRelativelyPrimeInt(pk0.N)
    ry := common.GetRandomPositiveRelativelyPrimeInt(pk1.N)
    gamma := common.GetRandomPositiveInt(q3NCap)
    m := common.GetRandomPositiveInt(qNCap)
    delta := common.GetRandomPositiveInt(q3NCap)
    mu := common.GetRandomPositiveInt(qNCap)

    // Fig 15.1 compute
    modNSquared := common.ModInt(NSquared)
    A := modNSquared.Exp(C, alpha)
    A = modNSquared.Mul(A, modNSquared.Exp(pk0.Gamma(), beta))
    A = modNSquared.Mul(A, modNSquared.Exp(r, pk0.N))
	alphaModQ := new(big.Int).Mod(alpha, ec.Params().N)
    Bx := crypto.ScalarBaseMult(ec, alphaModQ)
    modN1Squared := common.ModInt(pk1.NSquare())
    By := modN1Squared.Mul(modN1Squared.Exp(pk1.Gamma(), beta), modN1Squared.Exp(ry, pk1.N))

    modNCap := common.ModInt(NCap)
    E := modNCap.Exp(s, alpha)
    E = modNCap.Mul(E, modNCap.Exp(t, gamma))
    S := modNCap.Exp(s, x)
    S = modNCap.Mul(S, modNCap.Exp(t, m))
    F := modNCap.Exp(s, beta)
    F = modNCap.Mul(F, modNCap.Exp(t, delta))
    T := modNCap.Exp(s, y)
    T = modNCap.Mul(T, modNCap.Exp(t, mu))
    
    // Fig 15.2
    var e *big.Int
    {
        eHash := common.SHA512_256i(append([]*big.Int{}, pk0.N, pk1.N, Y, X.X(), X.Y(), C, D, Bx.X(), Bx.Y(), By, S, T, A, E, F)...)
        e = common.RejectionSample(q, eHash)
    }

    // Fig 15.3
    z1 := new(big.Int).Mul(e, x)
    z1 = z1.Add(z1, alpha)
    z2 := new(big.Int).Mul(e, y)
    z2 = z2.Add(z2, beta)
    z3 := new(big.Int).Mul(e, m)
    z3 = z3.Add(z3, gamma)
    z4 := new(big.Int).Mul(e, mu)
    z4 = z4.Add(z4, delta)
    modN := common.ModInt(pk0.N)
    w := modN.Exp(rho, e)
    w = modN.Mul(w, r)
    modN1 := common.ModInt(pk1.N)
    wy := modN1.Exp(rhoy, e)
    wy = modN1.Mul(wy, ry)

    return &ProofAffg{S: S, T: T, A: A, Bx: Bx, By: By, E: E, F: F, Z1: z1, Z2: z2, Z3: z3, Z4: z4, W: w, Wy: wy}, nil
}

func NewProofFromBytes(ec elliptic.Curve, bzs [][]byte) (*ProofAffg, error) {
    if !common.NonEmptyMultiBytes(bzs, ProofAffgBytesParts) {
    return nil, fmt.Errorf(
        "expected %d byte parts to construct ProofAffg", ProofAffgBytesParts)
    }

    point, err := crypto.NewECPoint(ec,
        new(big.Int).SetBytes(bzs[3]),
        new(big.Int).SetBytes(bzs[4]))
    if err != nil {
        return nil, err
    }

    return &ProofAffg{
        S:    new(big.Int).SetBytes(bzs[0]),
        T:    new(big.Int).SetBytes(bzs[1]),
        A:    new(big.Int).SetBytes(bzs[2]),
        Bx:   point,
        By:   new(big.Int).SetBytes(bzs[5]),
        E: 	  new(big.Int).SetBytes(bzs[6]),
        F:    new(big.Int).SetBytes(bzs[7]),
        Z1:   new(big.Int).SetBytes(bzs[8]),
        Z2:   new(big.Int).SetBytes(bzs[9]),
        Z3:   new(big.Int).SetBytes(bzs[10]),
        Z4:   new(big.Int).SetBytes(bzs[11]),
        W:    new(big.Int).SetBytes(bzs[12]),
        Wy:   new(big.Int).SetBytes(bzs[13]),
    }, nil
}

// ProveAffg.Verify implements verification of aff-g proof
func (pf *ProofAffg) Verify(ec elliptic.Curve, pk0 *paillier.PublicKey, pk1 *paillier.PublicKey, NCap, s, t, C, D, Y *big.Int, X *crypto.ECPoint) bool {
    if pf == nil || !pf.ValidateBasic() || ec == nil || pk0 == nil || pk1 == nil || NCap == nil || s == nil || t == nil || C == nil || D == nil || Y == nil || X == nil {
        return false
    }

    q := ec.Params().N
    q3 := new(big.Int).Mul(q, q)
    q3 = new(big.Int).Mul(q, q3)
    q6 := new(big.Int).Mul(q3, q3)

    // Fig 15. Range Check
    if pf.Z1.Cmp(q3) > 0 {
        return false
    }

    if pf.Z2.Cmp(q6) > 0 {
        return false
    }

    var e *big.Int
    {
        eHash := common.SHA512_256i(append([]*big.Int{}, pk0.N, pk1.N, Y, X.X(), X.Y(), C, D, pf.Bx.X(), pf.Bx.Y(), pf.By, pf.S, pf.T, pf.A, pf.E, pf.F)...)
        e = common.RejectionSample(q, eHash)
    }

    // Fig 15. Equality Check
    var left, right *big.Int
    {
        modNSquared := common.ModInt(pk0.NSquare())

        CEXPz1 := modNSquared.Exp(C, pf.Z1)
        Np1EXPz2 := modNSquared.Exp(pk0.Gamma(), pf.Z2)
        wEXPN := modNSquared.Exp(pf.W, pk0.N)
        left = modNSquared.Mul(CEXPz1, wEXPN)
        left = modNSquared.Mul(left, Np1EXPz2)

        DEXPe := modNSquared.Exp(D, e)
        right = modNSquared.Mul(DEXPe, pf.A)
        if left.Cmp(right) != 0 {
            return false
        }
    }

    {
        z1ModQ := new(big.Int).Mod(pf.Z1, ec.Params().N)
        gEXPz1 := crypto.ScalarBaseMult(ec, z1ModQ)
        BxXEXPe, err := X.ScalarMult(e).Add(pf.Bx)
        if err != nil || !gEXPz1.Equals(BxXEXPe) {
            return false
        }
    }

    {
        modN1Squared := common.ModInt(pk1.NSquare())

        N1p1EXPz2 := modN1Squared.Exp(pk1.Gamma(), pf.Z2)
        wyEXPN := modN1Squared.Exp(pf.Wy, pk1.N)
        left = modN1Squared.Mul(N1p1EXPz2, wyEXPN)

        YEXPe := modN1Squared.Exp(Y, e)
        right = modN1Squared.Mul(YEXPe, pf.By)
        if left.Cmp(right) != 0 {
            return false
        }
    }

    {
        modNCap := common.ModInt(NCap)
        {
            sExpz1 := modNCap.Exp(s, pf.Z1)
            tExpz3 := modNCap.Exp(t, pf.Z3)
            left = modNCap.Mul(sExpz1, tExpz3)
            SEXPe := modNCap.Exp(pf.S, e)
            right = modNCap.Mul(SEXPe, pf.E)
            if left.Cmp(right) != 0 {
                return false
            }
        }

        {
            sEXPz2 := modNCap.Exp(s, pf.Z2)
            tEXPz4 := modNCap.Exp(t, pf.Z4)
            left = modNCap.Mul(sEXPz2, tEXPz4)
            TEXPe := modNCap.Exp(pf.T, e)
            right = modNCap.Mul(TEXPe, pf.F)
            if left.Cmp(right) != 0 {
                return false
            }
        }
    }


    return true
}

func (pf *ProofAffg) ValidateBasic() bool {
    return pf.S != nil &&
           pf.T != nil &&
           pf.A != nil &&
           pf.Bx != nil &&
           pf.By != nil &&
           pf.E != nil &&
           pf.F != nil &&
           pf.Z1 != nil &&
           pf.Z3 != nil &&
           pf.Z2 != nil &&
           pf.Z4 != nil && 
           pf.W != nil &&
           pf.Wy != nil
           
}

func (pf *ProofAffg) Bytes() [ProofAffgBytesParts][]byte {
    return [...][]byte{
        pf.S.Bytes(),
        pf.T.Bytes(),
        pf.A.Bytes(),
        pf.Bx.X().Bytes(),
        pf.Bx.Y().Bytes(),
        pf.By.Bytes(),
        pf.E.Bytes(),
        pf.F.Bytes(),
        pf.Z1.Bytes(),
        pf.Z2.Bytes(),
        pf.Z3.Bytes(),
        pf.Z4.Bytes(),
        pf.W.Bytes(),
        pf.Wy.Bytes(),
    }
}
