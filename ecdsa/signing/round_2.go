package signing

import (
	"errors"

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

	// it's concurrency time...
	errChs1 := make([]chan *tss.Error, len(round.Parties().IDs()))
	for j := range errChs1 {
		if j == i {
			errChs1[j] = nil
			continue
		}
		errChs1[j] = make(chan *tss.Error)
	}
	errChs2 := make([]chan *tss.Error, len(round.Parties().IDs()))
	for j := range errChs2 {
		if j == i {
			errChs2[j] = nil
			continue
		}
		errChs2[j] = make(chan *tss.Error)
	}

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		// Bob_mid
		go func(j int, Pj *tss.PartyID) {
			beta, c1ji, _, pi1ji, err := mta.BobMid(
				round.key.PaillierPks[j],
				round.temp.signRound1MtAInitMessages[j].Pi,
				round.temp.gamma,
				round.temp.signRound1MtAInitMessages[j].C,
				round.key.NTildej[j],
				round.key.H1j[j],
				round.key.H2j[j],
				round.key.NTildej[i],
				round.key.H1j[i],
				round.key.H2j[i])
			// should be thread safe as these are pre-allocated
			round.temp.betas[j] = beta
			round.temp.c1jis[j] = c1ji
			round.temp.pi1jis[j] = pi1ji
			if err == nil {
				errChs1[j] <- nil
				return
			}
			errChs1[j] <- round.WrapError(err, Pj)
		}(j, Pj)
		// Bob_mid_wc
		go func(j int, Pj *tss.PartyID) {
			v, c2ji, _, pi2ji, err := mta.BobMidWC(
				round.key.PaillierPks[j],
				round.temp.signRound1MtAInitMessages[j].Pi,
				round.temp.w,
				round.temp.signRound1MtAInitMessages[j].C,
				round.key.NTildej[j],
				round.key.H1j[j],
				round.key.H2j[j],
				round.key.NTildej[i],
				round.key.H1j[i],
				round.key.H2j[i],
				round.temp.bigWs[i])
			round.temp.vs[j] = v
			round.temp.c2jis[j] = c2ji
			round.temp.pi2jis[j] = pi2ji
			if err == nil {
				errChs2[j] <- nil
				return
			}
			errChs2[j] <- round.WrapError(err, Pj)
		}(j, Pj)
	}
	// consume error channels; wait for goroutines
	culprits := make([]*tss.PartyID, 0, len(round.Parties().IDs()))
	for _, errCh := range append(errChs1, errChs2...) {
		if errCh == nil { continue }
		if err := <-errCh; err != nil {
			culprits = append(culprits, err.Culprits()...)
		}
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("failed to calculate Bob_mid or Bob_mid_wc"), culprits...)
	}
	// create and send messages
	for j, Pj := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		r2msg := NewSignRound2MtAMidMessage(
			Pj, round.PartyID(), round.temp.c1jis[j], round.temp.pi1jis[j], round.temp.c2jis[j], round.temp.pi2jis[j])
		round.temp.signRound2MtAMidMessages[round.PartyID().Index] = &r2msg
		round.out <- r2msg
	}
	return nil
}

func (round *round2) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound2MtAMidMessages {
		if round.ok[j] {
			continue
		}
		if !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*SignRound2MtAMidMessage); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
