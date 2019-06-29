package signing

import (
	"errors"
	"fmt"

	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 2
	round.started = true
	round.resetOk()

	i := round.PartyID().Index
	for j, Pj := range round.Parties().Parties() {
		if j == round.PartyID().Index {
			continue
		}
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
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to calculate bob_mid: %v", err))
		}
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
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to calculate bob_mid_wc: %v", err))
		}

		round.temp.betas[j] = beta
		round.temp.vs[j] = v
		r2msg := NewSignRound2MtAMidMessage(Pj, round.PartyID(), c1ji, pi1ji, c2ji, pi2ji)
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
