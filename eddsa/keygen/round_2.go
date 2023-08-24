// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"

	errors2 "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index

	// 4. store r1 message pieces
	for j, msg := range round.temp.kgRound1Messages {
		r1msg := msg.Content().(*KGRound1Message)
		round.temp.KGCs[j] = r1msg.UnmarshalCommitment()
	}

	// 3. p2p send share ij to Pj
	shares := round.temp.shares
	for j, Pj := range round.Parties().IDs() {
		r2msg1 := NewKGRound2Message1(Pj, round.PartyID(), shares[j])
		// do not send to this Pj, but store for round 3
		if j == i {
			round.temp.kgRound2Message1s[j] = r2msg1
			continue
		}
		round.temp.kgRound2Message1s[i] = r2msg1
		round.out <- r2msg1
	}

	// 5. compute Schnorr prove
	ContextI := append(round.temp.ssid, new(big.Int).SetUint64(uint64(i)).Bytes()...)
	pii, err := schnorr.NewZKProof(ContextI, round.temp.ui, round.temp.vs[0])
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "NewZKProof(ui, vi0)"))
	}

	// 5. BROADCAST de-commitments of Shamir poly*G and Schnorr prove
	r2msg2 := NewKGRound2Message2(round.PartyID(), round.temp.deCommitPolyG, pii)
	round.temp.kgRound2Message2s[i] = r2msg2
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*KGRound2Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	// guard - VERIFY de-commit for all Pj
	for j, msg := range round.temp.kgRound2Message1s {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		msg2 := round.temp.kgRound2Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
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
