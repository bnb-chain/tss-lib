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

	"github.com/btcsuite/btcd/btcec"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

// One Round Finalization (called async/offline)

const (
	TaskNameFinalize = "signing-finalize"
)

// FinalizeGetOurSigShare is called in one-round signing mode after the online rounds have finished to compute s_i.
func FinalizeGetOurSigShare(state *common.SignatureData, msg *big.Int) (sI *big.Int) {
	data := state.GetOneRoundData()

	N := tss.EC().Params().N
	modN := common.ModInt(N)

	// bigR is stored as bytes for the OneRoundData protobuf struct
	bigRXBz, bigRYBz := data.GetBigRX(), data.GetBigRY()
	bigRX, bigRY := new(big.Int).SetBytes(bigRXBz), new(big.Int).SetBytes(bigRYBz)
	bigR := crypto.NewECPointNoCurveCheck(tss.EC(), bigRX, bigRY)

	kI, sigmaI := new(big.Int).SetBytes(data.GetKI()), new(big.Int).SetBytes(data.GetSigmaI())
	rIX := new(big.Int).Mod(bigR.X(), N)
	sI = modN.Add(modN.Mul(msg, kI), modN.Mul(rIX, sigmaI))
	return
}

// FinalizeGetOurSigShare is called in one-round signing mode to build a final signature given others' s_i shares and a msg.
// Note: each P in otherPs should correspond with that P's s_i at the same index in otherSIs.
func FinalizeGetAndVerifyFinalSig(
	state *common.SignatureData,
	pk *ecdsa.PublicKey,
	msg *big.Int,
	ourP *tss.PartyID,
	ourSI *big.Int,
	otherPs []*tss.PartyID,
	otherSIs []*big.Int,
) (*common.SignatureData, *btcec.Signature, *tss.Error) {
	if len(otherPs) == 0 || len(otherPs) != len(otherSIs) {
		return nil, nil, FinalizeWrapError(errors.New("len(otherPs) == 0 || len(otherPs) != len(otherSIs)"), ourP)
	}
	data := state.GetOneRoundData()

	N := tss.EC().Params().N
	modN := common.ModInt(N)

	sumS := ourSI
	for _, sJ := range otherSIs {
		sumS = modN.Add(sumS, sJ)
	}

	rI, err := crypto.NewECPoint(tss.EC(),
		new(big.Int).SetBytes(data.GetBigRX()),
		new(big.Int).SetBytes(data.GetBigRY()))
	if err != nil {
		return nil, nil, FinalizeWrapError(err, ourP)
	}
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	recId := 0
	if rI.X().Cmp(N) > 0 {
		recId = 2
	}
	if rI.Y().Bit(0) != 0 {
		recId |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	secp256k1halfN := new(big.Int).Rsh(N, 1)
	if sumS.Cmp(secp256k1halfN) > 0 {
		sumS.Sub(N, sumS)
		recId ^= 1
	}

	ok := ecdsa.Verify(pk, msg.Bytes(), rI.X(), sumS)
	if !ok {
		return nil, nil, FinalizeWrapError(fmt.Errorf("signature verification failed"), ourP)
	}

	// save the signature for final output
	r, s := rI.X(), sumS
	state.R, state.S = r.Bytes(), s.Bytes()
	state.Signature = append(rI.X().Bytes(), sumS.Bytes()...)
	state.SignatureRecovery = []byte{byte(recId)}
	state.M = msg.Bytes()

	return state, &btcec.Signature{R: r, S: s}, nil
}

func FinalizeWrapError(err error, victim *tss.PartyID, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskNameFinalize, -1, victim, culprits...)
}

// Full Online Finalization

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 8
	round.started = true
	round.resetOK()

	Ps := round.Parties().IDs()
	Pi := round.PartyID()
	i := Pi.Index

	ourSI := round.temp.sI
	otherSIs := make([]*big.Int, 0, len(Ps)-1)
	otherPs := make([]*tss.PartyID, 0, len(Ps)-1)
	for j := range round.temp.signRound7Messages {
		if j == i {
			continue
		}
		r7msg := round.temp.signRound7Messages[j].Content().(*SignRound7Message)
		sI := r7msg.GetSI()
		otherSIs = append(otherSIs, new(big.Int).SetBytes(sI))
		otherPs = append(otherPs, Ps[j])
	}

	pk := &ecdsa.PublicKey{
		Curve: tss.EC(),
		X:     round.key.ECDSAPub.X(),
		Y:     round.key.ECDSAPub.Y(),
	}
	data, _, err := FinalizeGetAndVerifyFinalSig(round.data, pk, round.temp.m, round.PartyID(), ourSI, otherPs, otherSIs)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.data = data
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
