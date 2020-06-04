// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round7) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 7
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	// bigR is stored as bytes for the OneRoundData protobuf struct
	bigRX, bigRY := new(big.Int).SetBytes(round.temp.BigRX), new(big.Int).SetBytes(round.temp.BigRY)
	bigR := crypto.NewECPointNoCurveCheck(tss.EC(), bigRX, bigRY)

	h, err := crypto.ECBasePoint2(tss.EC())
	if err != nil {
		return round.WrapError(err, Pi)
	}

	bigSIProducts := (*crypto.ECPoint)(nil)
	for j, msg := range round.temp.signRound6Messages {
		Pj := round.Parties().IDs()[j]
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		r6msg := msg.Content().(*SignRound6Message)

		TI, err := r3msg.UnmarshalTI()
		if err != nil {
			return round.WrapError(err, Pj)
		}
		bigSI, err := r6msg.UnmarshalSI()
		if err != nil {
			return round.WrapError(err, Pj)
		}

		// ZK STProof check
		stProof, err := r6msg.UnmarshalSTProof()
		if err != nil {
			return round.WrapError(err, Pj)
		}
		if ok := stProof.Verify(bigSI, TI, bigR, h); !ok {
			return round.WrapError(errors.New("STProof verify failure"), Pj)
		}

		// bigSI consistency check
		if bigSIProducts == nil {
			bigSIProducts = bigSI
			continue
		}
		if bigSIProducts, err = bigSIProducts.Add(bigSI); err != nil {
			return round.WrapError(err, Pj)
		}
	}
	{
		y := round.key.ECDSAPub
		if bigSIProducts.X().Cmp(y.X()) != 0 || bigSIProducts.Y().Cmp(y.Y()) != 0 {
			return round.WrapError(errors.New("consistency check failed; y != products"))
		}
	}
	round.temp.rI = bigR

	// PRE-PROCESSING FINISHED
	// If we are in one-round signing mode (msg is nil), we will exit out with the current state here and we are done.
	round.data.OneRoundData = &round.temp.SignatureData_OneRoundData
	if round.temp.m == nil {
		round.end <- *round.data
		return nil
	}

	// Continuing the full online protocol.
	sI := FinalizeGetOurSigShare(round.data, round.temp.m)
	round.temp.sI = sI

	r7msg := NewSignRound7Message(round.PartyID(), sI)
	round.temp.signRound7Messages[i] = r7msg
	round.out <- r7msg
	return nil
}

func (round *round7) Update() (bool, *tss.Error) {
	// If we are in one-round signing mode (msg is nil) there are no further rounds.
	if round.temp.m == nil {
		return false, nil
	}
	// Continuing the full online protocol.
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
	// If we are in one-round signing mode (msg is nil) there are no further rounds.
	if round.temp.m == nil {
		return false
	}
	// Continuing the full online protocol.
	if _, ok := msg.Content().(*SignRound7Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round7) NextRound() tss.Round {
	// If we are in one-round signing mode (msg is nil), we will exit out with the current state here and there are no further rounds.
	if round.temp.m == nil {
		return nil
	}
	// Continuing the full online protocol.
	round.started = false
	return &finalization{round}
}
