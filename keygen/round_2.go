package keygen

import (
	"errors"

	"github.com/binance-chain/tss-lib/types"
)

func (round *round2) start() *keygenError {
	if round.started {
		return round.wrapError(errors.New("round already started"), nil)
	}
	round.number = 2
	round.started = true
	round.resetOk()

	// 4. store r1 message pieces
	for j, r1msg := range round.temp.kgRound1CommitMessages {
		round.save.PaillierPks[j] = &r1msg.PaillierPk // used in round 4
		round.save.NTildej[j] = r1msg.NTildei
		round.save.H1j[j], round.save.H2j[j] = r1msg.H1i, r1msg.H2i
		round.temp.KGCs[j] = &r1msg.Commitment // C is temporary
	}

	// 3. p2p send share ij to Pj
	shares := round.temp.shares
	for j, Pj := range round.p2pCtx.Parties() {
		r2msg1 := NewKGRound2VssMessage(Pj, round.partyID, shares[j])
		// do not send to this Pj, but store for round 3
		if j == round.partyID.Index {
			round.temp.kgRound2VssMessages[j] = &r2msg1
			continue
		}
		round.temp.kgRound2VssMessages[round.partyID.Index] = &r2msg1
		round.out <- r2msg1
	}

	// 5. BROADCAST de-commitments of Shamir poly*G
	r2msg2 := NewKGRound2DeCommitMessage(round.partyID, round.temp.deCommitPolyG)
	round.temp.kgRound2DeCommitMessages[round.partyID.Index] = &r2msg2
	round.out <- r2msg2

	return nil
}

func (round *round2) canAccept(msg types.Message) bool {
	if msg1, ok := msg.(*KGRound2VssMessage); !ok || msg1 == nil {
		if msg2, ok := msg.(*KGRound2DeCommitMessage); !ok || msg2 == nil {
			return false
		}
	}
	return true
}

func (round *round2) update() (bool, *keygenError) {
	// guard - VERIFY de-commit for all Pj
	for j, msg := range round.temp.kgRound2VssMessages {
		if round.ok[j] { continue }
		if !round.canAccept(msg) {
			return false, nil
		}
		msg2 := round.temp.kgRound2DeCommitMessages[j]
		if !round.canAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) nextRound() round {
	round.started = false
	return &round3{round}
}
