// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true

	// Fig 5. Round 1. private key part
	ui := common.GetRandomPositiveInt(round.Params().EC().Params().N)

	// Fig 5. Round 1. pub key part, vss shares
	ids := round.Parties().IDs().Keys()
	vs, shares, err := vss.Create(round.Params().EC(), round.Threshold(), ui, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	// security: the original u_i may be discarded
	ui = zero // clears the secret data from memory
	_ = ui    // silences a linter warning

	// Fig 6. Round 1. // TODO modify GeneartePreParams accordingly
	var preParams *LocalPreParams
	if round.save.LocalPreParams.Validate() {
		preParams = &round.save.LocalPreParams
	} else {
		preParams, err = GeneratePreParams(round.SafePrimeGenTimeout(), 3)
		if err != nil {
			return round.WrapError(errors.New("pre-params generation failed"), Pi)
		}
	}

	listToHash, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	listToHash = append(listToHash, preParams.PaillierSK.PublicKey.N, preParams.NTildei, preParams.H1i, preParams.H2i)
	VHash := common.SHA512_256i(listToHash...)
	// BROADCAST VHash
	{
		msg := NewKGRound1Message(round.PartyID(), VHash)
		round.temp.kgRound1Messages[i] = msg // TODO remove
		round.out <- msg
	}

	// round.temp.ui = ui
	round.temp.r1msgVHashs[i] = VHash
	round.save.Ks = ids
	round.save.LocalPreParams = *preParams
	round.save.NTildej[i] = preParams.NTildei
	round.save.H1j[i], round.save.H2j[i] = preParams.H1i, preParams.H2i
	// for this P: SAVE
	// - shareID
	// and keep in temporary storage:
	// - VSS Vs
	// - our set of Shamir shares
	round.save.ShareID = ids[i]
	round.temp.r2msgVss[i] = vs
	round.temp.shares = shares
	// for this P: SAVE paillier keys
	round.save.PaillierSK = preParams.PaillierSK
	round.save.PaillierPKs[i] = &preParams.PaillierSK.PublicKey
	//round.temp.deCommitPolyG = cmt.D

	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.kgRound1Messages {
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

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
