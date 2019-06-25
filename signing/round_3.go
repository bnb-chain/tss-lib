package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 3
	round.started = true
	round.resetOk()

	var alphas = make([]*big.Int, len(round.Parties().Parties()))
	for j, _ := range round.Parties().Parties() {
		if j != round.PartyID().Index {
			alphaIj, err := mta.AliceEnd(round.key.PaillierPks[round.PartyID().Index], nil, nil, nil, nil, round.temp.signRound2MtAMidMessages[j].C1_ji, nil, round.key.PaillierSk)
			if err != nil {
				return round.WrapError(fmt.Errorf("failed to compute Alice_end: %v", err))
			}
			alphas[j] = alphaIj
		}
	}

	thelta := &big.Int{}
	thelta = thelta.Mul(round.temp.k, round.temp.gamma)
	thelta = thelta.Mod(thelta, tss.EC().Params().N)

	// TODO: round.temp.w is not there because of preparation phase is not implemented
	//sigma := &big.Int{}
	//sigma = sigma.Mul(round.temp.k, round.temp.w)
	//sigma = sigma.Mod(sigma, tss.EC().Params().N)

	for j, _ := range round.Parties().Parties() {
		if j != round.PartyID().Index {
			thelta = thelta.Add(thelta, alphas[j].Add(alphas[j], round.temp.betas[j]))
			thelta = thelta.Mod(thelta, tss.EC().Params().N)
		}
	}

	round.temp.thelta = thelta
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
