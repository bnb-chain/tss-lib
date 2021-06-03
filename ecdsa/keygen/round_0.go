// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"

	"github.com/binance-chain/tss-lib/crypto/safeparameter"
	"github.com/binance-chain/tss-lib/tss"
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound0(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- LocalPartySaveData) tss.Round {
	return &round0{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
	}
}

// in round0 we run the check of the parameter
func (round *round0) Start() *tss.Error {
	round.number = 0
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	var err error
	var preParams *safeparameter.LocalPreParams
	if round.save.LocalPreParams.Validate() && !round.save.LocalPreParams.ValidateWithProof() {
		return round.WrapError(
			errors.New("`optionalPreParams` failed to validate; it might have been generated with an older version of tss-lib"))
	} else if round.save.LocalPreParams.ValidateWithProof() {
		preParams = &round.save.LocalPreParams
	} else {
		preParams, err = safeparameter.GeneratePaiBlumPreParams(round.SafePrimeGenTimeout(), 3)
		if err != nil {
			return round.WrapError(errors.New("pre-params generation failed"), Pi)
		}
	}
	round.save.LocalPreParams = *preParams
	round.save.NTildej[i] = preParams.NTildei
	round.save.H1j[i], round.save.H2j[i] = preParams.H1i, preParams.H2i

	omega := safeparameter.GenOmega(round.save.NTildei)
	msg, err := NewKGRound0Message(Pi, omega)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.temp.kgRound0Messages[i] = msg
	round.out <- msg
	return nil
}

func (round *round0) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound0Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round0) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.kgRound0Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		// vss check is in round 2
		round.ok[j] = true
	}
	return true, nil
}

func (round *round0) NextRound() tss.Round {
	round.started = false
	return &round1{round}
}
