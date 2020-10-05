// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round7) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 7
	round.started = true
	round.resetOK()

	UX, UY := round.temp.Ui.X(), round.temp.Ui.Y()
	TX, TY := round.temp.Ti.X(), round.temp.Ti.Y()
	for j, Pj := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}

		r5msg := round.temp.signRound5Messages[j].Content().(*SignRound5Message)
		r6msg := round.temp.signRound6Messages[j].Content().(*SignRound6Message)
		cj, dj := r5msg.UnmarshalCommitment(), r6msg.UnmarshalDeCommitment()
		cmt := commitments.HashCommitDecommit{C: cj, D: dj}
		ok, values := cmt.DeCommit()
		if !ok && len(values) != 4 {
			return round.WrapError(errors.New("de-commitment for bigVj and bigAj failed"), Pj)
		}
		UjX, UjY, TjX, TjY := values[0], values[1], values[2], values[3]
		UX, UY = tss.EC().Add(UX, UY, UjX, UjY)
		TX, TY = tss.EC().Add(TX, TY, TjX, TjY)
	}

	if UX.Cmp(TX) != 0 || UY.Cmp(TY) != 0 {
		return round.WrapError(errors.New("U doesn't equal T"), round.PartyID())
	}
	r7msg := NewSignRound7Message(round.PartyID(), encodedBytesToBigInt(round.temp.si))
	round.temp.signRound7Messages[round.PartyID().Index] = r7msg
	round.out <- r7msg
	return nil
}

func (round *round7) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound7Messages {
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

func (round *round7) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound7Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round7) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
