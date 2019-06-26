package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

// missing:
// line5: SchnorrVerify
// all lines after line7
func (round *round5) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 5
	round.started = true
	round.resetOk()

	RX, RY := tss.EC().ScalarBaseMult(round.temp.gamma.Bytes())
	R := crypto.NewECPoint(tss.EC(), RX, RY)
	for j, Pj := range round.Parties().Parties() {
		if j == round.PartyID().Index {
			continue
		}
		SCj := round.temp.signRound1CommitMessages[j].Commitment
		SDj := round.temp.signRound4DecommitMessage[j].Decommitment
		cmtDeCmt := commitments.HashCommitDecommit{C: SCj, D: SDj}
		ok, BigGammaJ := cmtDeCmt.DeCommit()
		if !ok {
			return round.WrapError(errors.New("commitment verify failed"), Pj)
		}
		// TODO: line 5 SchnorrVerify
		RXNew, RYNew := tss.EC().Add(R.X(), R.Y(), BigGammaJ[0], BigGammaJ[1])
		R = crypto.NewECPoint(tss.EC(), RXNew, RYNew)
	}
	finalRX, finalRY := tss.EC().ScalarMult(R.X(), R.Y(), round.temp.thelta_inverse.Bytes())
	round.data.R = crypto.NewECPoint(tss.EC(), finalRX, finalRY)
	return nil
}

func (round *round5) Update() (bool, *tss.Error) {
	// TODO: this update logic should be changed
	for j, _ := range round.ok {
		round.ok[j] = true
	}

	return true, nil
}

func (round *round5) CanAccept(msg tss.Message) bool {
	return true
}

func (round *round5) NextRound() tss.Round {
	// TODO: procceding
	//round.started = false
	//return &round6{round}
	return nil
}
