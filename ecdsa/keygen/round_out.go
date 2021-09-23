// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *roundout) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	Ps := round.Parties().IDs()
	PIDs := Ps.Keys()

	// 1-3. (concurrent)
	// r3 messages are assumed to be available and != nil in this function
	r3msgs := round.temp.kgRound3Messages
	chs := make([]chan bool, len(r3msgs))
	for i := range chs {
		chs[i] = make(chan bool)
	}
	for j, msg := range round.temp.kgRound3Messages {
		if j == i {
			continue
		}
		r4msg := msg.Content().(*KGRound4Message)
		go func(prf paillier.Proof, j int, ch chan<- bool) {
			ppk := round.save.PaillierPKs[j]
			ok, err := prf.Verify(ppk.N, PIDs[j], round.save.ECDSAPub)
			if err != nil {
				common.Logger.Error(round.WrapError(err, Ps[j]).Error())
				ch <- false
				return
			}
			ch <- ok
		}(r4msg.UnmarshalProofInts(), j, chs[j])
	}

	// consume unbuffered channels (end the goroutines)
	for j, ch := range chs {
		if j == i {
			round.ok[j] = true
			continue
		}
		round.ok[j] = <-ch
	}
	culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
	for j, ok := range round.ok {
		if !ok {
			culprits = append(culprits, Ps[j])
			common.Logger.Warningf("paillier verify failed for party %s", Ps[j])
			continue
		}
		common.Logger.Debugf("paillier verify passed for party %s", Ps[j])

	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("paillier verify failed"), culprits...)
	}

	round.end <- *round.save

	return nil
}

func (round *roundout) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *roundout) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *roundout) NextRound() tss.Round {
	return nil // finished!
}
