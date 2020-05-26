// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round6) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 6
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	bigRBarIProducts := (*crypto.ECPoint)(nil)
	for j, msg := range round.temp.signRound5Messages {
		Pj := round.Parties().IDs()[j]
		r5msg := msg.Content().(*SignRound5Message)
		bigRBarI, err := r5msg.UnmarshalRI()
		if err != nil {
			return round.WrapError(err, Pj)
		}
		if bigRBarIProducts == nil {
			bigRBarIProducts = bigRBarI
			continue
		}
		if bigRBarIProducts, err = bigRBarIProducts.Add(bigRBarI); err != nil {
			return round.WrapError(err, Pj)
		}
	}
	{
		ec := tss.EC()
		gX, gY := ec.Params().Gx, ec.Params().Gy
		if bigRBarIProducts.X().Cmp(gX) != 0 || bigRBarIProducts.Y().Cmp(gY) != 0 {
			return round.WrapError(errors.New("consistency check failed; g != products"))
		}
	}

	bigR, sigmaI, TI, lI := round.temp.bigR, round.temp.sigmaI, round.temp.TI, round.temp.lI
	bigSI := bigR.ScalarMult(sigmaI)

	h, err := crypto.ECBasePoint2(tss.EC())
	if err != nil {
		return round.WrapError(err, Pi)
	}
	stProof, err := zkp.NewSTProof(TI, bigR, h, sigmaI, lI)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	r6msg := NewSignRound6Message(Pi, bigSI, stProof)
	round.temp.signRound6Messages[i] = r6msg
	round.out <- r6msg
	return nil
}

func (round *round6) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound6Messages {
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

func (round *round6) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound6Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round6) NextRound() tss.Round {
	round.started = false
	return &round7{round}
}
