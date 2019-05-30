package keygen

import (
	"fmt"
	"math/big"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/types"
)

type (
	partyState struct {
		partyID *types.PartyID
		isLocal bool

		p2pCtx   *types.PeerContext
		kgParams KGParameters
		monitor  partyStateMonitor

		currentRound int
		lastMessages []types.Message

		kgRound1CommitMessages   []*KGRound1CommitMessage
		kgRound2VssMessages      []*KGRound2VssMessage
		kgRound2DeCommitMessages []*KGRound2DeCommitMessage
		kgRound3ZKUProofMessage  []*KGRound3ZKUProofMessage

		// keygen state
		uiGs [][]*big.Int
	}

	partyStateMonitor interface {
		notifyKeygenRound1Complete()
		notifyKeygenRound2Complete()
		notifyKeygenRound3Complete()
	}
)

var _ types.Party = (*partyState)(nil)

func newPartyState(
		p2pCtx *types.PeerContext,
		kgParams KGParameters,
		partyID *types.PartyID,
		isLocal bool,
		monitor partyStateMonitor) *partyState {

	currentRound := 1
	partyCount := kgParams.partyCount

	return &partyState{
		partyID: partyID,
		isLocal: isLocal,

		p2pCtx:   p2pCtx,
		kgParams: kgParams,
		monitor:  monitor,

		currentRound: currentRound,
		lastMessages: make([]types.Message, partyCount),

		kgRound1CommitMessages:   make([]*KGRound1CommitMessage, partyCount),
		kgRound2VssMessages:      make([]*KGRound2VssMessage, partyCount),
		kgRound2DeCommitMessages: make([]*KGRound2DeCommitMessage, partyCount),
		kgRound3ZKUProofMessage:  make([]*KGRound3ZKUProofMessage, partyCount),

		// misc state
		uiGs: make([][]*big.Int, partyCount),
	}
}

// implements Stringer
func (p *partyState) String() string {
	return fmt.Sprintf("id: %s, isLocal: %t, round: %d", p.partyID.String(), p.isLocal, p.currentRound)
}

func (p *partyState) ID() *types.PartyID {
	return p.partyID
}

func (p *partyState) IsLocal() bool {
	return p.isLocal
}

func (p *partyState) CurrentRound() int {
	return p.currentRound
}

func (p *partyState) Update(msg types.Message) (bool, error) {
	if msg.GetFrom() == nil {
		return false, p.wrapError(errors.New("Update received nil msg"), p.currentRound)
	}
	if msg == nil {
		return false, fmt.Errorf("nil message received by party %s", p.partyID)
	}

	common.Logger.Infof("party %s received message: %s", p.partyID, msg.String())

	fromPIdx := msg.GetFrom().Index

	defer func(fromPIdx int) {
		p.lastMessages[fromPIdx] = msg
	}(fromPIdx)

	common.Logger.Infof("party %s update for: %s", p.partyID, msg.String())
	switch msg.(type) {

	case KGRound1CommitMessage: // Round 1 broadcast messages
		// guard - ensure no last message from Pi
		if p.lastMessages[fromPIdx] != nil {
			return false, nil
		}
		p1msg := msg.(KGRound1CommitMessage)
		p.kgRound1CommitMessages[fromPIdx] = &p1msg
		return p.tryNotifyRound1Complete(p1msg)

	case KGRound2VssMessage: // Round 2 P2P messages
		// TODO guard - verify lastMessage from Pi (security)
		p2msg1 := msg.(KGRound2VssMessage)
		p.kgRound2VssMessages[fromPIdx] = &p2msg1 // just collect
		if p2msg2 := p.kgRound2DeCommitMessages[fromPIdx]; p2msg2 != nil {
			return p.tryNotifyRound2Complete(p2msg1, *p2msg2)
		}
		return false, nil

	case KGRound2DeCommitMessage:
		// TODO guard - verify lastMessage from Pi (security)
		p2msg2 := msg.(KGRound2DeCommitMessage)
		p.kgRound2DeCommitMessages[fromPIdx] = &p2msg2
		if p2msg1 := p.kgRound2VssMessages[fromPIdx]; p2msg1 != nil {
			return p.tryNotifyRound2Complete(*p2msg1, p2msg2)
		}
		return false, nil

	case KGRound3ZKUProofMessage:
		// TODO guard - verify lastMessage from Pi (security)
		p3msg := msg.(KGRound3ZKUProofMessage)
		p.kgRound3ZKUProofMessage[fromPIdx] = &p3msg
		return p.tryNotifyRound3Complete(p3msg)

	default: // unrecognised message!
		return false, fmt.Errorf("unrecognised message: %v", msg)
	}

	return true, nil
}

func (p *partyState) tryNotifyRound1Complete(p1msg KGRound1CommitMessage) (bool, error) {
	// guard - VERIFY received paillier pk/proof for Pi
	if ok := p1msg.PaillierPf.Verify(&p1msg.PaillierPk); !ok {
		return false, p.wrapError(fmt.Errorf("verify paillier proof failed (from party %s)", p1msg.From), 1)
	}

	// guard - COUNT the required number of messages
	var toCheck = make([]interface{}, len(p.kgRound1CommitMessages))
	for i, m := range p.kgRound1CommitMessages {
		if m != nil {
			toCheck[i] = m
		}
	}
	if !p.hasRequiredMessages(toCheck) {
		common.Logger.Debugf("party %s: waiting for more kgRound1CommitMessages", p.partyID)
		return false, nil
	}

	// continue - round 2, vss generate
	p.currentRound++
	if p.monitor != nil {
		p.monitor.notifyKeygenRound1Complete()
	}
	return true, nil
}

func (p *partyState) tryNotifyRound2Complete(p2msg1 KGRound2VssMessage, p2msg2 KGRound2DeCommitMessage) (bool, error) {
	fromPIdx := p2msg2.From.Index

	// guard - VERIFY and STORE de-commitment
	cmt := p.kgRound1CommitMessages[fromPIdx].Commitment
	cmtDeCmt := commitments.HashCommitDecommit{C: cmt, D: p2msg2.DeCommitment}
	ok, uiG, err := cmtDeCmt.DeCommit()
	if err != nil {
		return false, p.wrapError(err, 2)
	}
	if !ok {
		return false, p.wrapError(fmt.Errorf("decommitment failed (from party %s == %s)", p2msg1.From, p2msg2.From), 2)
	}
	p.uiGs[fromPIdx] = uiG

	// guard - VERIFY VSS check for Pi
	polyGs := p2msg2.PolyGs
	if p2msg1.PiShare.Verify(polyGs) == false {
		return false, p.wrapError(fmt.Errorf("vss verify failed (from party %s == %s)", p2msg1.From, p2msg2.From), 2)
	}

	// guard - COUNT the required number of messages
	var toCheck = make([]interface{}, len(p.kgRound2VssMessages))
	for i, m := range p.kgRound2VssMessages {
		if m != nil {
			toCheck[i] = m
		}
	}
	if !p.hasRequiredMessages(toCheck) {
		common.Logger.Debugf("party %s: waiting for more kgRound2VssMessages", p.partyID)
		return false, nil
	}
	// guard - COUNT the required number of messages
	var toCheck2 = make([]interface{}, len(p.kgRound2DeCommitMessages))
	for i, m := range p.kgRound2DeCommitMessages {
		if m != nil {
			toCheck2[i] = m
		}
	}
	if !p.hasRequiredMessages(toCheck2) {
		common.Logger.Debugf("party %s: waiting for more kgRound2DeCommitMessages", p.partyID)
		return false, nil
	}

	// continue - round 3
	p.currentRound++
	if p.monitor != nil {
		p.monitor.notifyKeygenRound2Complete()
	}
	return true, nil
}

func (p *partyState) tryNotifyRound3Complete(p3msg KGRound3ZKUProofMessage) (bool, error) {
	fromPIdx := p3msg.From.Index

	// guard - VERIFY zk proof of ui
	uiG := p.uiGs[fromPIdx]
	if ok := p3msg.ZKUProof.Verify(uiG); !ok {
		common.Logger.Debugf("party %s: waiting for more kgRound2DeCommitMessages", p.partyID)
		return false, p.wrapError(fmt.Errorf("zk verify ui failed (from party %s)", p3msg.From), 3)
	}

	// guard - COUNT the required number of messages
	var toCheck = make([]interface{}, len(p.kgRound3ZKUProofMessage))
	for i, m := range p.kgRound3ZKUProofMessage {
		if m != nil {
			toCheck[i] = m
		}
	}
	if !p.hasRequiredMessages(toCheck) {
		return false, nil
	}

	// continue - completion
	p.currentRound = -1
	if p.monitor != nil {
		p.monitor.notifyKeygenRound3Complete()
	}
	return true, nil
}

func (p *partyState) hasRequiredMessages(arr []interface{}) bool {
	for _, v := range arr {
		_, ok := v.(types.Message)
		if !ok || v == nil {
			return false
		}
	}
	return true
}

func (p *partyState) wrapError(err error, round int) error {
	return errors.Wrapf(err, "party %s, round %d", p.partyID, round)
}
