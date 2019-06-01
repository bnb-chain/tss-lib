package keygen

import (
	"errors"
	"fmt"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/types"
)

func (round *round2) roundNumber() int {
	return 2
}

func (round *round2) start() error {
	if round.started {
		return round.wrapError(errors.New("round already started"))
	}
	round.started = true

	// next step: compute the vss shares
	ids := round.p2pCtx.Parties().Keys()
	vsp, polyGs, shares, err := vss.Create(round.params().Threshold(), round.temp.Ui, ids)
	if err != nil {
		panic(round.wrapError(err))
	}

	// for this P: SAVE Xi (combined Shamir shares)
	if round.save.Xi, err = shares.Combine(); err != nil {
		return err
	}

	// for this P: SAVE shareIdx
	round.save.ShareID = ids[round.partyID.Index]

	// for this P: SAVE UiPolyGs
	round.save.UiPolyGs = polyGs

	// p2p send share ij to Pj
	for j, Pj := range round.p2pCtx.Parties() {
		p2msg1 := NewKGRound2VssMessage(Pj, round.partyID, shares[j])
		// do not send to this Pj, but store for round 3
		if j == round.partyID.Index {
			round.temp.kgRound2VssMessages[j] = &p2msg1
			continue
		}
		round.temp.kgRound2VssMessages[round.partyID.Index] = &p2msg1
		round.out <- p2msg1
	}

	// BROADCAST de-commitments and Shamir poly * Gs
	p2msg2 := NewKGRound2DeCommitMessage(round.partyID, vsp, polyGs, round.temp.DeCommitUiG)
	round.temp.kgRound2DeCommitMessages[round.partyID.Index] = &p2msg2
	round.out <- p2msg2
	return nil
}

func (round *round2) canAccept(msg types.Message) bool {
	if _, ok := msg.(KGRound2VssMessage); !ok {
		if _, ok := msg.(KGRound2DeCommitMessage); !ok {
			return false
		}
	}
	return true
}

func (round *round2) update(msg types.Message) (bool, error) {
	if !round.canAccept(msg) { // double check
		return false, nil
	}

	fromPIdx := msg.GetFrom().Index
	if round.temp.kgRound2DeCommitMessages[fromPIdx] == nil {
		return false, nil  // wait for it
	}

	switch msg.(type) {
	case KGRound2VssMessage: // Round 2 P2P messages
		// TODO guard - verify lastMessage from Pi (security)
		p2msg1 := msg.(KGRound2VssMessage)
		p2msg2 := round.temp.kgRound2DeCommitMessages[fromPIdx]
		// guard - VERIFY VSS check for Pi
		polyGs := p2msg2.PolyGs
		if p2msg1.PiShare.Verify(polyGs) == false {
			return false, round.wrapError(fmt.Errorf("vss verify failed (from party %s == %s)", p2msg1.From, p2msg2.From))
		}

	case KGRound2DeCommitMessage:
		// de-commit happens in round 3

	default: // unrecognised message!
		return false, round.wrapError(fmt.Errorf("unrecognised message: %v", msg))
	}

	// compute BigXj

	return true, nil
}

func (round *round2) canProceed() bool {
	for i := 0; i < round.params().partyCount; i++ {
		if round.temp.kgRound2VssMessages[i] == nil {
			common.Logger.Debugf("party %s: waiting for more kgRound2VssMessages", round.partyID)
			return false
		}
	}
	for i := 0; i < round.params().partyCount; i++ {
		if round.temp.kgRound2DeCommitMessages[i] == nil {
			common.Logger.Debugf("party %s: waiting for more kgRound2DeCommitMessages", round.partyID)
			return false
		}
	}
	return true
}

func (round *round2) nextRound() round {
	if !round.canProceed() {
		return round
	}
	return &round3{round, false}
}
