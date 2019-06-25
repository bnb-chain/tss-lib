package signing

import (
	"errors"
	"fmt"

	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/tss"
)

// missing:
// line2: Bob_mid should return a ciphertext Cb and pi (range proof)
// line3: Bob_mid_wc should be implemented
func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 2
	round.started = true
	round.resetOk()

	for j, Pj := range round.Parties().Parties() {
		beta, c1ji, _, _, err := mta.BobMid(round.key.PaillierPks[j], round.temp.gamma, round.temp.signRound1MtAInitMessages[j].C, nil, nil, nil, nil, nil, nil)
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to calculate bob_mid: %v", err))
		}

		round.temp.betas[j] = beta
		r2msg := NewSignRound2MtAMidMessage(Pj, round.PartyID(), c1ji, nil, nil, nil)
		if j == round.PartyID().Index {
			round.temp.signRound2MtAMidMessages[j] = &r2msg
			continue
		}
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
