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

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/v4/tss"
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

	q := round.Params().EC().Params().N
	modN := common.ModInt(q)

	// SECURITY: reject a non-canonical peer theta rather than
	// normalising it. An honest theta leaves round 3 through modN.Add and is
	// therefore always in [0, q), so neither test below can reject one. A peer
	// that sends more bytes than the order needs, or a value at or above the
	// order, is sending something no honest run produces: the length test bounds
	// what SetBytes is asked to materialise, and the range test stops the silent
	// reduction that would otherwise accept two distinct encodings of one scalar.
	//
	// The bound is the curve order, so it cannot live in ValidateBasic: that is a
	// no-argument method on the message and the curve is supplied by the caller.
	// The EdDSA side caps its own scalar field with a constant only because that
	// protocol is single-curve. This is the same layering constraint already
	// recorded for the round-2 de-commitment count in key generation.
	qBytes := (q.BitLen() + 7) / 8
	for j, Pj := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		theltaJ := r3msg.GetTheta()
		if len(theltaJ) > qBytes {
			return round.WrapError(errors.New("theta is longer than the curve order"), Pj)
		}
		theltaJInt := new(big.Int).SetBytes(theltaJ)
		if theltaJInt.Cmp(q) >= 0 {
			return round.WrapError(errors.New("theta is not a canonical scalar"), Pj)
		}
		thetaInverse = modN.Add(thetaInverse, theltaJInt)
	}

	// compute the multiplicative inverse thelta mod q
	if common.IsConstantTimeEnabled() {
		// SECURITY: Use constant-time modular inverse for secret theta
		// See: https://github.com/golang/go/issues/20654
		ctModN := common.NewCTModInt(round.Params().EC().Params().N)
		thetaInverse = ctModN.ModInverseCT(thetaInverse)
	} else {
		thetaInverse = modN.ModInverse(thetaInverse)
	}
	if thetaInverse == nil {
		return round.WrapError(errors.New("theta inverse is nil"))
	}
	i := round.PartyID().Index
	ContextI := append(round.temp.ssid, new(big.Int).SetUint64(uint64(i)).Bytes()...)
	piGamma, err := schnorr.NewZKProof(ContextI, round.temp.gamma, round.temp.pointGamma, round.Rand())
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
	ret := true
	for j, msg := range round.temp.signRound4Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
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
