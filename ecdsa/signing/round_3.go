package signing

import (
	"errors"
	"math/big"
	"sync"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	var alphas = make([]*big.Int, len(round.Parties().IDs()))
	var us = make([]*big.Int, len(round.Parties().IDs()))

	i := round.PartyID().Index

	// it's concurrency time...
	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*2)
	wg := sync.WaitGroup{}
	wg.Add((len(round.Parties().IDs()) - 1) * 2)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		// Alice_end
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			alphaIj, err := mta.AliceEnd(
				round.key.PaillierPks[i],
				round.temp.signRound2MtAMidMessages[j].Pi1Ji,
				round.key.H1j[i],
				round.key.H2j[i],
				round.temp.signRound1SentMtaInitMessages[j].C,
				round.temp.signRound2MtAMidMessages[j].C1Ji,
				round.key.NTildej[i],
				round.key.PaillierSk)
			alphas[j] = alphaIj
			if err != nil {
				errChs <- round.WrapError(err, Pj)
			}
		}(j, Pj)
		// Alice_end_wc
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			uIj, err := mta.AliceEndWC(
				round.key.PaillierPks[i],
				round.temp.signRound2MtAMidMessages[j].Pi2Ji,
				round.temp.bigWs[j],
				round.temp.signRound1SentMtaInitMessages[j].C,
				round.temp.signRound2MtAMidMessages[j].C2Ji,
				round.key.NTildej[i],
				round.key.H1j[i],
				round.key.H2j[i],
				round.key.PaillierSk)
			us[j] = uIj
			if err != nil {
				errChs <- round.WrapError(err, Pj)
			}
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
		return round.WrapError(errors.New("failed to calculate Alice_end or Alice_end_wc"), culprits...)
	}

	modN := common.ModInt(tss.EC().Params().N)
	thelta := modN.Mul(round.temp.k, round.temp.gamma)
	sigma := modN.Mul(round.temp.k, round.temp.w)

	for j := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		thelta = modN.Add(thelta, alphas[j].Add(alphas[j], round.temp.betas[j]))
		sigma = modN.Add(sigma, us[j].Add(us[j], round.temp.vs[j]))
	}

	round.temp.thelta = thelta
	round.temp.sigma = sigma
	r3msg := NewSignRound3Message(round.PartyID(), thelta)
	round.temp.signRound3Messages[round.PartyID().Index] = &r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound3Messages {
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

func (round *round3) CanAccept(msg tss.Message) bool {
	if msg, ok := msg.(*SignRound3Message); !ok || msg == nil {
		return false
	}
	return true
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
