package keygen

import (
	"errors"
	"fmt"

	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/types"
)

func (round *round2) start() error {
	if round.started {
		return round.wrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOk()

	// p2p send share ij to Pj
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

	// BROADCAST de-commitments of Shamir poly*G
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

func (round *round2) update() (bool, error) {
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
		// de-commitment pre-verify
		C, D := round.temp.kgRound1CommitMessages[j].Commitment, msg2.DeCommitment
		CDCmt := &commitments.HashCommitDecommit{C, D}
		ok, err := CDCmt.Verify()
		if err != nil {
			return false, round.wrapError(err)
		}
		if !ok {
			return false, round.wrapError(fmt.Errorf("decommitment verify failed (from party %s)", msg.From))
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) nextRound() round {
	round.started = false
	return &round3{round}
}
