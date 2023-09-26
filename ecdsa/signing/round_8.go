// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

func (round *round8) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 8
	round.started = true
	round.resetOK()

	r8msg := NewSignRound8Message(round.PartyID(), round.temp.DTelda)
	round.temp.signRound8Messages[round.PartyID().Index] = r8msg
	round.out <- r8msg

	return nil
}

func (round *round8) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound8Messages {
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

func (round *round8) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound8Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round8) NextRound() tss.Round {
	round.started = false
	return &round9{round}
}
