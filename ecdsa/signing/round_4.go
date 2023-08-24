// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"

	errors2 "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	theta := *round.temp.theta
	thetaInverse := &theta

	modN := common.ModInt(round.Params().EC().Params().N)

	for j := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		theltaJ := r3msg.GetTheta()
		thetaInverse = modN.Add(thetaInverse, new(big.Int).SetBytes(theltaJ))
	}

	// compute the multiplicative inverse thelta mod q
	thetaInverse = modN.ModInverse(thetaInverse)
	i := round.PartyID().Index
	ContextI := append(round.temp.ssid, new(big.Int).SetUint64(uint64(i)).Bytes()...)
	piGamma, err := schnorr.NewZKProof(ContextI, round.temp.gamma, round.temp.pointGamma)
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "NewZKProof(gamma, bigGamma)"))
	}
	round.temp.thetaInverse = thetaInverse
	r4msg := NewSignRound4Message(round.PartyID(), round.temp.deCommit, piGamma)
	round.temp.signRound4Messages[round.PartyID().Index] = r4msg
	round.out <- r4msg

	return nil
}

func (round *round4) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound4Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round5{round}
}
