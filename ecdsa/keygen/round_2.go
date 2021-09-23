// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

// round 2 represents round 2 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true

	// Fig 5. Round 2. / Fig 6. Round 2.
	// BROADCAST message
	{
		//TODO
		// fmt.Println("vs[0].x", i, round.temp.vs[0].X()) //TODO
		msg := NewKGRound2Message(round.PartyID(), round.temp.vs, &round.save.PaillierSK.PublicKey, round.save.NTildei, round.save.H1i, round.save.H2i)
		// round.temp.kgRound2Messages[i] = msg
		round.out <- msg
	}

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r2msgVss {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
