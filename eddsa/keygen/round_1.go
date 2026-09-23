// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	cmts "github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

var zero = big.NewInt(0)

// nonPositiveNonceErrText is worded identically at every round-1 site that
// reads Parameters.SessionNonce().
const nonPositiveNonceErrText = "session nonce must be positive; call " +
	"Parameters.SetSessionNonce with a positive value agreed by all parties " +
	"before starting the round"

// round 1 represents round 1 of the keygen part of the EDDSA TSS spec
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- *LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
	}
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

	// Require caller-provided SessionNonce — see ecdsa/keygen/round_1.go
	// for full rationale.
	if nonce := round.Params().SessionNonce(); nonce != nil {
		// See ecdsa/keygen/round_1.go: the SSID hash takes Bytes(), the
		// magnitude only, so -n and +n collide and 0 is one constant for
		// every session.
		if nonce.Sign() <= 0 {
			return round.WrapError(errors.New(nonPositiveNonceErrText))
		}
		round.temp.ssidNonce = new(big.Int).Set(nonce)
	} else {
		return round.WrapError(errors.New(
			"keygen requires a session nonce; call Parameters.SetSessionNonce " +
				"with a value agreed by all parties before starting the round"))
	}
	ssid, err := round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}
	round.temp.ssid = ssid

	// 1. calculate "partial" key share ui
	ui := common.GetRandomPositiveInt(round.PartialKeyRand(), round.Params().EC().Params().N)
	round.temp.ui = ui

	// 2. compute the vss shares
	ids := round.Parties().IDs().Keys()
	vs, shares, err := vss.Create(round.EC(), round.Threshold(), ui, ids, round.Rand())
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.save.Ks = ids

	// security: the original u_i may be discarded
	ui = zero // clears the secret data from memory
	_ = ui    // silences a linter warning

	// 3. make commitment -> (C, D)
	pGFlat, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	cmt := cmts.NewHashCommitment(round.Rand(), pGFlat...)

	// for this P: SAVE
	// - shareID
	// and keep in temporary storage:
	// - VSS Vs
	// - our set of Shamir shares
	round.save.ShareID = ids[i]
	round.temp.vs = vs
	round.temp.shares = shares

	round.temp.deCommitPolyG = cmt.D

	// BROADCAST commitments
	{
		msg := NewKGRound1Message(round.PartyID(), cmt.C)
		round.temp.kgRound1Messages[i] = msg
		round.out <- msg
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.kgRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		// vss check is in round 2
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
