// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"sync"

	errorspkg "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*2)
	wg := sync.WaitGroup{}
	wg.Add((len(round.Parties().IDs()) - 1) * 2)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		// Bob_mid
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			r1msg := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
			rangeProofAliceJ, err := r1msg.UnmarshalRangeProofAlice()
			if err != nil {
				errChs <- round.WrapError(errorspkg.Wrapf(err, "MtA: UnmarshalRangeProofAlice failed"), Pj)
				return
			}
			betaJI, c1JI, _, pi1JI, err := mta.BobMid(
				round.key.PaillierPKs[j],
				rangeProofAliceJ,
				round.temp.gammaI,
				r1msg.UnmarshalC(),
				round.key.NTildej[j],
				round.key.H1j[j],
				round.key.H2j[j],
				round.key.NTildej[i],
				round.key.H1j[i],
				round.key.H2j[i])
			if err != nil {
				errChs <- round.WrapError(err, Pj)
				return
			}
			// should be thread safe as these are pre-allocated
			round.temp.betas[j] = betaJI
			round.temp.r5AbortData.BetaJI[j] = betaJI.Bytes()
			round.temp.pI1JIs[j] = pi1JI
			round.temp.c1JIs[j] = c1JI
		}(j, Pj)
		// Bob_mid_wc
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			r1msg := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
			rangeProofAliceJ, err := r1msg.UnmarshalRangeProofAlice()
			if err != nil {
				errChs <- round.WrapError(errorspkg.Wrapf(err, "MtA: UnmarshalRangeProofAlice failed"), Pj)
				return
			}
			vJI, c2JI, pi2JI, err := mta.BobMidWC(
				round.key.PaillierPKs[j],
				rangeProofAliceJ,
				round.temp.wI,
				r1msg.UnmarshalC(),
				round.key.NTildej[j],
				round.key.H1j[j],
				round.key.H2j[j],
				round.key.NTildej[i],
				round.key.H1j[i],
				round.key.H2j[i],
				round.temp.bigWs[i])
			if err != nil {
				errChs <- round.WrapError(err, Pj)
				return
			}
			round.temp.vJIs[j] = vJI
			round.temp.pI2JIs[j] = pi2JI
			round.temp.c2JIs[j] = c2JI
		}(j, Pj)
	}
	// consume error channels; wait for goroutines
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0, len(round.Parties().IDs()))
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("MtA: failed to verify Bob_mid or Bob_mid_wc"), culprits...)
	}
	// create and send messages
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		r2msg := NewSignRound2Message(
			Pj, round.PartyID(),
			round.temp.c1JIs[j],
			round.temp.pI1JIs[j],
			round.temp.c2JIs[j],
			round.temp.pI2JIs[j])
		round.out <- r2msg
	}
	return nil
}

func (round *round2) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound2Messages {
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

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound2Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
