package keygen

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOk()

	// 4. store r1 message pieces
	for j, r1msg := range round.temp.kgRound1CommitMessages {
		round.save.PaillierPks[j] = r1msg.PaillierPk // used in round 4
		round.save.NTildej[j] = r1msg.NTildei
		round.save.H1j[j], round.save.H2j[j] = r1msg.H1i, r1msg.H2i
		round.temp.KGCs[j] = &r1msg.Commitment // C is temporary
	}

	// 3. p2p send share ij to Pj
	shares := round.temp.shares
	for j, Pj := range round.Parties().IDs() {
		r2msg1 := NewKGRound2VssMessage(Pj, round.PartyID(), shares[j])
		// do not send to this Pj, but store for round 3
		if j == round.PartyID().Index {
			round.temp.kgRound2VssMessages[j] = &r2msg1
			continue
		}
		round.temp.kgRound2VssMessages[round.PartyID().Index] = &r2msg1
		round.out <- r2msg1
	}

	// 5. BROADCAST de-commitments of Shamir poly*G
	r2msg2 := NewKGRound2DeCommitMessage(round.PartyID(), round.temp.deCommitPolyG)
	round.temp.kgRound2DeCommitMessages[round.PartyID().Index] = &r2msg2
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg tss.Message) bool {
	if msg1, ok := msg.(*KGRound2VssMessage); !ok || msg1 == nil {
		if msg2, ok := msg.(*KGRound2DeCommitMessage); !ok || msg2 == nil {
			return false
		}
	}
	return true
}

func (round *round2) Update() (bool, *tss.Error) {
	// guard - VERIFY de-commit for all Pj
	for j, msg := range round.temp.kgRound2VssMessages {
		if round.ok[j] {
			continue
		}
		if !round.CanAccept(msg) {
			return false, nil
		}
		msg2 := round.temp.kgRound2DeCommitMessages[j]
		if !round.CanAccept(msg2) {
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
