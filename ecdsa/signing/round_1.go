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

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v2/crypto/mta"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

var zero = big.NewInt(0)

// round 1 represents round 1 of the signing part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- *common.SignatureData) tss.Round {
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
	if round.temp.m.Cmp(round.Params().EC().Params().N) >= 0 {
		return round.WrapError(errors.New("hashed message is not valid"))
	}

	round.number = 1
	round.started = true
	round.resetOK()
	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	ssid, err := round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}
	round.temp.ssid = ssid

	k := common.GetRandomPositiveInt(round.Rand(), round.EC().Params().N)
	gamma := common.GetRandomPositiveInt(round.Rand(), round.EC().Params().N)

	pointGamma := crypto.ScalarBaseMult(round.Params().EC(), gamma)
	cmt := commitments.NewHashCommitment(round.Rand(), pointGamma.X(), pointGamma.Y())
	round.temp.k = k
	round.temp.gamma = gamma
	round.temp.pointGamma = pointGamma
	round.temp.deCommit = cmt.D

	i := round.PartyID().Index
	round.ok[i] = true

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		cA, pi, err := mta.AliceInit(round.Params().EC(), round.key.PaillierPKs[i], k, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.Rand())
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to init mta: %v", err))
		}
		r1msg1 := NewSignRound1Message1(Pj, round.PartyID(), cA, pi)
		round.temp.cis[j] = cA
		round.out <- r1msg1
	}

	r1msg2 := NewSignRound1Message2(round.PartyID(), cmt.C)
	round.temp.signRound1Message2s[i] = r1msg2
	round.out <- r1msg2

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg1 := range round.temp.signRound1Message1s {
		if round.ok[j] {
			continue
		}
		if msg1 == nil || !round.CanAccept(msg1) {
			return false, nil
		}
		msg2 := round.temp.signRound1Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound1Message2); ok {
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

	xi := round.key.Xi
	ks := round.key.Ks
	bigXs := round.key.BigXj

	if round.temp.keyDerivationDelta != nil {
		// adding the key derivation delta to the xi's
		// Suppose x has shamir shares x_0,     x_1,     ..., x_n
		// So x + D has shamir shares  x_0 + D, x_1 + D, ..., x_n + D
		mod := common.ModInt(round.Params().EC().Params().N)
		xi = mod.Add(round.temp.keyDerivationDelta, xi)
		round.key.Xi = xi
	}

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi, bigWs := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, bigXs)

	round.temp.w = wi
	round.temp.bigWs = bigWs
	return nil
}
