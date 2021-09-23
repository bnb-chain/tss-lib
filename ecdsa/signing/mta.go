// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	zkpaffg "github.com/binance-chain/tss-lib/crypto/zkp/affg"
)

type MtAOut struct {
    Dji *big.Int
    Fji *big.Int
    Sij *big.Int
    Rij *big.Int
    Beta *big.Int
    Proofji *zkpaffg.ProofAffg
}

func NewMtA(ec elliptic.Curve, Kj *big.Int, gammai *big.Int, BigGammai *crypto.ECPoint, pkj *paillier.PublicKey, pki *paillier.PublicKey, NCap, s, t *big.Int) (*MtAOut, error) {
	q := ec.Params().N
    q3 := new(big.Int).Mul(q, q)
    q3 = new(big.Int).Mul(q, q3)
	
	betaNeg := common.GetRandomPositiveInt(q3)

    gammaK, err := pkj.HomoMult(gammai, Kj)
    if err != nil {
        return nil, err
    }
    Dji, sij, err := pkj.EncryptAndReturnRandomness(betaNeg)
    if err != nil {
        return nil, err
    }
    Dji, err = pkj.HomoAdd(gammaK, Dji)
    if err != nil {
        return nil, err
    }

    Fji, rij, err := pki.EncryptAndReturnRandomness(betaNeg)
    if err != nil {
        return nil, err
    }

    // q := ec.Params().N
    beta := common.ModInt(q).Sub(zero, betaNeg)

    Psiji, err := zkpaffg.NewProof(ec, pkj, pki, NCap, s, t, Kj, Dji, Fji, BigGammai, gammai, betaNeg, sij, rij)
    if err != nil {
        return nil, err
    }

    return &MtAOut{
        Dji:    Dji,
        Fji:    Fji,
        Sij:    sij,
        Rij:    rij,
        Beta:   beta,
        Proofji:  Psiji,
    }, nil
}
