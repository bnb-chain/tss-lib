package keygen

import (
	"fmt"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/types"
)

var _ partyState = (*round2)(nil)

func NewRound2State(r1 *round1) partyState {
	return &round2{
		r1,
		make([]*KGRound2VssMessage, r1.kgParams.partyCount),
		make([]*KGRound2DeCommitMessage, r1.kgParams.partyCount),
	}
}

func (round *round2) start() error {
	// next step: compute the vss shares
	ids := round.p2pCtx.Parties().Keys()
	vsp, polyGs, shares, err := vss.Create(round.kgParams.Threshold(), round.savedData.Ui, ids)
	if err != nil {
		panic(round.wrapError(err, 1))
	}

	// for this P: SAVE UiPolyGs
	round.savedData.UiPolyGs = polyGs

	// p2p send share ij to Pj
	for i, Pi := range round.p2pCtx.Parties() {
		p2msg1 := NewKGRound2VssMessage(Pi, round.partyID, shares[i])
		// do not send to this Pi, but store for round 3
		if i == round.partyID.Index {
			round.kgRound2VssMessages[i] = &p2msg1
			continue
		}
		round.msgSender.updateAndSendMsg(p2msg1)
	}

	// BROADCAST de-commitments and Shamir poly * Gs
	p2msg2 := NewKGRound2DeCommitMessage(round.partyID, vsp, polyGs, round.savedData.DeCommitUiG)
	round.msgSender.updateAndSendMsg(p2msg2)

	common.Logger.Infof("party %s: keygen round 2 started", round.partyID)

	return nil
}

func (round *round2) Update(msg types.Message) (bool, error) {
	ok, err := round.validateBasis(msg)
	if !ok || err != nil {
		return ok, err
	}

	fromPIdx := msg.GetFrom().Index

	defer func(fromPIdx int) {
		round.lastMessages[fromPIdx] = msg
	}(fromPIdx)

	common.Logger.Infof("party %s update for: %s", round.partyID, msg.String())
	switch msg.(type) {
	case KGRound2VssMessage: // Round 2 P2P messages
		// TODO guard - verify lastMessage from Pi (security)
		p2msg1 := msg.(KGRound2VssMessage)
		round.kgRound2VssMessages[fromPIdx] = &p2msg1 // just collect
		if p2msg2 := round.kgRound2DeCommitMessages[fromPIdx]; p2msg2 != nil {
			return round.tryNotifyRound2Complete(p2msg1, *p2msg2)
		}
		return true, nil

	case KGRound2DeCommitMessage:
		// TODO guard - verify lastMessage from Pi (security)
		p2msg2 := msg.(KGRound2DeCommitMessage)
		round.kgRound2DeCommitMessages[fromPIdx] = &p2msg2
		if p2msg1 := round.kgRound2VssMessages[fromPIdx]; p2msg1 != nil {
			return round.tryNotifyRound2Complete(*p2msg1, p2msg2)
		}
		return false, nil

	default: // unrecognised message!
		return false, fmt.Errorf("unrecognised message: %v", msg)
	}
}

func (round *round2) tryNotifyRound2Complete(p2msg1 KGRound2VssMessage, p2msg2 KGRound2DeCommitMessage) (bool, error) {
	fromPIdx := p2msg2.From.Index

	// guard - VERIFY and STORE de-commitment
	cmt := round.kgRound1CommitMessages[fromPIdx].Commitment
	cmtDeCmt := commitments.HashCommitDecommit{C: cmt, D: p2msg2.DeCommitment}
	ok, uiG, err := cmtDeCmt.DeCommit()
	if err != nil {
		return false, round.wrapError(err, 2)
	}
	if !ok {
		return false, round.wrapError(fmt.Errorf("decommitment failed (from party %s == %s)", p2msg1.From, p2msg2.From), 2)
	}
	round.uiGs[fromPIdx] = uiG

	// guard - VERIFY VSS check for Pi
	polyGs := p2msg2.PolyGs
	if p2msg1.PiShare.Verify(polyGs) == false {
		return false, round.wrapError(fmt.Errorf("vss verify failed (from party %s == %s)", p2msg1.From, p2msg2.From), 2)
	}

	// guard - COUNT the required number of messages
	if !round.hasRequiredMessages() {
		return false, nil
	}

	// continue - round 3
	round.currentRound++
	if round.monitor != nil {
		round.monitor.notifyKeygenRound2Complete()
	}
	return true, nil
}

func (round *round2) hasRequiredMessages() bool {
	for i := 0; i < round.kgParams.partyCount; i++ {
		if i != round.partyID.Index && round.kgRound2VssMessages[i] == nil {
			common.Logger.Debugf("party %s: waiting for more kgRound2VssMessages", round.partyID)
			return false
		}
	}

	// guard - COUNT the required number of messages
	for i := 0; i < round.kgParams.partyCount; i++ {
		if i != round.partyID.Index && round.kgRound2DeCommitMessages[i] == nil {
			common.Logger.Debugf("party %s: waiting for more kgRound2DeCommitMessages", round.partyID)
			return false
		}
	}

	return true
}
