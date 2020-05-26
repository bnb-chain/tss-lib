// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 8
	round.started = true
	round.resetOK()

	N := tss.EC().Params().N
	modN := common.ModInt(N)

	sumS := zero
	for j := range round.Parties().IDs() {
		r7msg := round.temp.signRound7Messages[j].Content().(*SignRound7Message)
		sI := r7msg.GetSI()
		sumS = modN.Add(sumS, new(big.Int).SetBytes(sI))
		round.ok[j] = true
	}

	recid := 0
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	if round.temp.rI.X().Cmp(N) > 0 {
		recid = 2
	}
	if round.temp.rI.Y().Bit(0) != 0 {
		recid |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	secp256k1halfN := new(big.Int).Rsh(N, 1)
	if sumS.Cmp(secp256k1halfN) > 0 {
		sumS.Sub(N, sumS)
		recid ^= 1
	}

	pk := ecdsa.PublicKey{
		Curve: tss.EC(),
		X:     round.key.ECDSAPub.X(),
		Y:     round.key.ECDSAPub.Y(),
	}
	ok := ecdsa.Verify(&pk, round.temp.m.Bytes(), round.temp.rI.X(), sumS)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}

	// save the signature for final output
	round.data.Signature = append(round.temp.rI.X().Bytes(), sumS.Bytes()...)
	round.data.SignatureRecovery = []byte{byte(recid)}
	round.data.R = round.temp.rI.X().Bytes()
	round.data.S = sumS.Bytes()
	round.data.M = round.temp.m.Bytes()

	round.end <- *round.data

	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
