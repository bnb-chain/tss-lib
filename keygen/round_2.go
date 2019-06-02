package keygen

import (
	"errors"
	"fmt"

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
	round.resetOk()

	// next step: compute the vss shares
	ids := round.p2pCtx.Parties().Keys()
	vsp, polyGs, shares, err := vss.Create(round.params().Threshold(), round.temp.ui, ids)
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
	p2msg2 := NewKGRound2DeCommitMessage(round.partyID, vsp, polyGs, round.temp.deCommitUiG)
	round.temp.kgRound2DeCommitMessages[round.partyID.Index] = &p2msg2
	round.out <- p2msg2
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
	// guard - VERIFY VSS check for all Pj
	for j, msg := range round.temp.kgRound2VssMessages {
		if round.ok[j] { continue }
		if !round.canAccept(msg) {
			return false, nil
		}
		msg2 := round.temp.kgRound2DeCommitMessages[j]
		if !round.canAccept(msg2) {
			return false, nil
		}
		polyGs := msg2.PolyGs
		if msg.PiShare.Verify(polyGs) == false {
			return false, round.wrapError(fmt.Errorf("vss verify failed (from party %s == %s)", msg.From, msg2.From))
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) nextRound() round {
	round.started = false
	return &round3{round}
}
