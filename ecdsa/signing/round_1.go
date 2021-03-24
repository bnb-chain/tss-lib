// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

var zero = big.NewInt(0)

// round 1 represents round 1 of the signing part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- *SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
	}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	// Spec requires calculate H(M) here,
	// but considered different blockchain use different hash function we accept the converted big.Int
	// if this big.Int is not belongs to Zq, the client might not comply with common rule (for ECDSA):
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L263
	if round.temp.m != nil &&
		round.temp.m.Cmp(tss.EC().Params().N) >= 0 {
		return round.WrapError(errors.New("hashed message is not valid"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true

	gammaI := common.GetRandomPositiveInt(tss.EC().Params().N)
	kI := common.GetRandomPositiveInt(tss.EC().Params().N)
	round.temp.gammaI = gammaI
	round.temp.r5AbortData.GammaI = gammaI.Bytes()

	gammaIG := crypto.ScalarBaseMult(tss.EC(), gammaI)
	round.temp.gammaIG = gammaIG

	cmt := commitments.NewHashCommitment(gammaIG.X(), gammaIG.Y())
	round.temp.deCommit = cmt.D

	// MtA round 1
	paiPK := round.key.PaillierPKs[i]
	cA, rA, err := paiPK.EncryptAndReturnRandomness(kI)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	witnessPartyID := (i + 1) % len(round.Parties().IDs())
	// set "k"-related temporary variables, also used for identified aborts later in the protocol
	{
		kIBz := kI.Bytes()
		round.temp.KI = kIBz // now part of the OneRoundData struct
		round.temp.r5AbortData.KI = kIBz
		round.temp.r7AbortData.KI = kIBz
		round.temp.cAKI = cA // used for the ZK proof in round 5
		round.temp.rAKI = rA
		round.temp.r7AbortData.KRandI = rA.Bytes()
	}

	pi, err := mta.AliceInit(paiPK, kI, cA, rA, round.key.NTildej[witnessPartyID], round.key.H1j[witnessPartyID], round.key.H2j[witnessPartyID])
	if err != nil {
		return round.WrapError(fmt.Errorf("failed to init mta: %v", err))
	}
	round.temp.rangeProof = pi
	round.temp.c1Is = cA

	r1msg1 := NewSignRound1Message(round.PartyID(), cA, round.temp.rangeProof, cmt.C)
	round.temp.signRound1Messages[i] = r1msg1
	round.out <- r1msg1
	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg1 := range round.temp.signRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg1 == nil || !round.CanAccept(msg1) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index
	xi, ks, bigXs := round.key.Xi, round.key.Ks, round.key.BigXj
	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	if wI, bigWs, err := PrepareForSigning(i, len(ks), xi, ks, bigXs); err != nil {
		return err
	} else {
		round.temp.wI = wI
		round.temp.bigWs = bigWs
	}
	return nil
}
