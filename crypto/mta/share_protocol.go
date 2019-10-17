// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

func AliceInit(
	pkA *paillier.PublicKey,
	a, NTildeB, h1B, h2B *big.Int,
) (cA *big.Int, pf *RangeProofAlice, err error) {
	cA, rA, err := pkA.EncryptAndReturnRandomness(a)
	if err != nil {
		return nil, nil, err
	}
	pf, err = ProveRangeAlice(pkA, cA, NTildeB, h1B, h2B, a, rA)
	return cA, pf, err
}

func BobMid(
	pkA *paillier.PublicKey,
	pf *RangeProofAlice,
	b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B *big.Int,
) (beta, cB, betaPrm *big.Int, piB *ProofBob, err error) {
	if !pf.Verify(pkA, NTildeB, h1B, h2B, cA) {
		err = errors.New("RangeProofAlice.Verify() returned false")
		return
	}
	q := tss.EC().Params().N
	betaPrm = common.GetRandomPositiveInt(pkA.N)
	cBetaPrm, cRand, err := pkA.EncryptAndReturnRandomness(betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAdd(cB, cBetaPrm)
	if err != nil {
		return
	}
	beta = common.ModInt(q).Sub(zero, betaPrm)
	piB, err = ProveBob(pkA, NTildeA, h1A, h2A, cA, cB, b, betaPrm, cRand)
	return
}

func BobMidWC(
	pkA *paillier.PublicKey,
	pf *RangeProofAlice,
	b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B *big.Int,
	B *crypto.ECPoint,
) (beta, cB, betaPrm *big.Int, piB *ProofBobWC, err error) {
	if !pf.Verify(pkA, NTildeB, h1B, h2B, cA) {
		err = errors.New("RangeProofAlice.Verify() returned false")
		return
	}
	q := tss.EC().Params().N
	betaPrm = common.GetRandomPositiveInt(pkA.N)
	cBetaPrm, cRand, err := pkA.EncryptAndReturnRandomness(betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAdd(cB, cBetaPrm)
	if err != nil {
		return
	}
	beta = common.ModInt(q).Sub(zero, betaPrm)
	piB, err = ProveBobWC(pkA, NTildeA, h1A, h2A, cA, cB, b, betaPrm, cRand, B)
	return
}

func AliceEnd(
	pkA *paillier.PublicKey,
	pf *ProofBob,
	h1A, h2A, cA, cB, NTildeA *big.Int,
	sk *paillier.PrivateKey,
) (*big.Int, error) {
	if !pf.Verify(pkA, NTildeA, h1A, h2A, cA, cB) {
		return nil, errors.New("ProofBob.Verify() returned false")
	}
	alphaPrm, err := sk.Decrypt(cB)
	if err != nil {
		return nil, err
	}
	q := tss.EC().Params().N
	return new(big.Int).Mod(alphaPrm, q), nil
}

func AliceEndWC(
	pkA *paillier.PublicKey,
	pf *ProofBobWC,
	B *crypto.ECPoint,
	cA, cB, NTildeA, h1A, h2A *big.Int,
	sk *paillier.PrivateKey,
) (*big.Int, error) {
	if !pf.Verify(pkA, NTildeA, h1A, h2A, cA, cB, B) {
		return nil, errors.New("ProofBobWC.Verify() returned false")
	}
	alphaPrm, err := sk.Decrypt(cB)
	if err != nil {
		return nil, err
	}
	q := tss.EC().Params().N
	return new(big.Int).Mod(alphaPrm, q), nil
}
