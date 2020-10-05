// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/crypto/schnorr"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	piAi, err := schnorr.NewZKProof(round.temp.roi, round.temp.bigAi)
	if err != nil {
		return round.WrapError(errors.Wrapf(err, "NewZKProof(roi, bigAi)"))
	}

	dSi := encodedBytesToBigInt(round.temp.si)
	sili := new(big.Int).Add(round.temp.li, dSi)
	piV, err := schnorr.NewZKProof(sili, round.temp.bigVi)
	if err != nil {
		return round.WrapError(errors.Wrapf(err, "NewZKVProof(bigVi, bigR, si, li)"))
	}

	r4msg := NewSignRound4Message(round.PartyID(), round.temp.DPower, piAi, piV)
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
