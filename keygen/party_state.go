package keygen

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/types"
)

type (
	PartyStateMonitor interface {
		notifyKeygenRound1Complete()
		notifyKeygenRound2Complete()
		notifyKeygenRound3Complete()
	}

	PartyState struct {
		partyID *types.PartyID
		isLocal bool

		p2pCtx   *types.PeerContext
		kgParams KGParameters
		monitor  PartyStateMonitor

		currentRound int
		lastMessages []types.Message

		kgRound1CommitMessages   []*KGRound1CommitMessage
		kgRound2VssMessages      []*KGRound2VssMessage
		kgRound2DeCommitMessages []*KGRound2DeCommitMessage
		kgRound3ZKUProofMessage  []*KGRound3ZKUProofMessage
	}
)

var _ types.Party = (*PartyState)(nil)

func NewPartyState(
	p2pCtx *types.PeerContext, kgParams KGParameters, partyID *types.PartyID, isLocal bool, monitor PartyStateMonitor) *PartyState {

	currentRound := 1
	partyCount := kgParams.partyCount

	return &PartyState{
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
	}
}

func (p *PartyState) IsLocal() bool {
	return p.isLocal
}

func (p *PartyState) CurrentRound() int {
	return p.currentRound
}

func (p *PartyState) Update(msg types.Message) (bool, error) {
	if msg.GetFrom() == nil {
		return false, p.wrapError(errors.New("Update received nil msg"), p.currentRound)
	}
	// P i != j
	if msg.GetFrom().Index == p.partyID.Index {
		return false, nil
	}
	if msg == nil {
		return false, fmt.Errorf("nil message received by party %s", p.partyID)
	}

	fmt.Printf("party %s received message: %s", p.partyID, msg.GetType())

	fromPIdx := msg.GetFrom().Index

	defer func(fromPIdx int) {
		p.lastMessages[fromPIdx] = msg
	}(fromPIdx)

	common.Logger.Info("Update for: ", msg)
	switch msg.(type) {

	case KGRound1CommitMessage: // Round 1 broadcast messages
		// guard - ensure no last message
		if p.lastMessages[fromPIdx] != nil {
			return false, p.wrapError(errors.New("unexpected lastMessage"), 1)
		}
		p1msg := msg.(KGRound1CommitMessage)
		p.kgRound1CommitMessages[fromPIdx] = &p1msg
		return p.tryNotifyRound1Complete(p1msg)

	case KGRound2VssMessage: // Round 2 P2P messages
		// guard - verify lastMessage
		if _, ok := p.lastMessages[fromPIdx].(KGRound1CommitMessage); !ok {
			return false, p.wrapError(errors.New("unexpected lastMessage"), 2)
		}
		p2msg1 := msg.(KGRound2VssMessage)
		p.kgRound2VssMessages[fromPIdx] = &p2msg1 // just collect
		return true, nil

	case KGRound2DeCommitMessage:
		// guard - verify lastMessage
		if _, ok := p.lastMessages[fromPIdx].(KGRound2VssMessage); !ok {
			return false, p.wrapError(errors.New("unexpected lastMessage"), 2)
		}
		p2msg2 := msg.(KGRound2DeCommitMessage)
		p.kgRound2DeCommitMessages[fromPIdx] = &p2msg2
		p2msg1 := p.kgRound2VssMessages[fromPIdx]
		return p.tryNotifyRound2Complete(*p2msg1, p2msg2)

	// TODO add round 3 case(s)

	default:
		return false, fmt.Errorf("unrecognised message: %v", msg)
	}

	return true, nil
}

func (p *PartyState) tryNotifyRound1Complete(p1msg KGRound1CommitMessage) (bool, error) {
	// guard - VERIFY received paillier pk/proof for Pi
	if ok := p1msg.PaillierPf.Verify(&p1msg.PaillierPk); !ok {
		return false, p.wrapError(fmt.Errorf("verify paillier proof failed (from party %s)", p1msg.From), 1)
	}
	// guard - do we have the required number of messages?
	var toCheck = make([]interface{}, len(p.kgRound1CommitMessages))
	for i, m := range p.kgRound1CommitMessages {
		toCheck[i] = m
	}
	if !p.hasRequiredMessages(toCheck) {
		return false, nil
	}
	// continue - round 2, vss generate
	p.currentRound++
	if p.monitor != nil {
		p.monitor.notifyKeygenRound1Complete()
	}
	return true, nil
}

func (p *PartyState) tryNotifyRound2Complete(p2msg1 KGRound2VssMessage, p2msg2 KGRound2DeCommitMessage) (bool, error) {
	fromPIdx := p2msg2.From.Index
	// guard - VERIFY de-commit and VSS checks for Pi
	cmt := p.kgRound1CommitMessages[fromPIdx].Commitment
	cmtDeCmt := commitments.HashCommitDecommit{cmt, p2msg2.DeCommitment}
	ok, err := cmtDeCmt.Verify()
	if err != nil {
		return false, p.wrapError(err, 2)
	}
	if !ok {
		return false, p.wrapError(fmt.Errorf("decommitment failed (from party %s = %s)", p2msg1.From, p2msg2.From), 2)
	}
	// guard - do we have the required number of messages?
	var toCheck = make([]interface{}, len(p.kgRound2DeCommitMessages))
	for i, m := range p.kgRound2DeCommitMessages {
		toCheck[i] = m
	}
	if !p.hasRequiredMessages(toCheck) {
		return false, nil
	}
	// guard - do we have the required number of messages?
	var toCheck2 = make([]interface{}, len(p.kgRound2DeCommitMessages))
	for i, m := range p.kgRound2DeCommitMessages {
		toCheck[i] = m
	}
	if !p.hasRequiredMessages(toCheck2) {
		return false, nil
	}
	// continue - round 3
	p.currentRound++
	if p.monitor != nil {
		p.monitor.notifyKeygenRound2Complete()
	}
	return true, nil
}

func (p *PartyState) tryNotifyRound3Complete() (bool, error) {
	// guard - do we have the required number of messages?
	var toCheck = make([]interface{}, len(p.kgRound3ZKUProofMessage))
	for i, m := range p.kgRound3ZKUProofMessage {
		toCheck[i] = m
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

func (p *PartyState) hasRequiredMessages(arr []interface{}) bool {
	firstNil := false // expect one nil (this party)
	for i := range arr {
		if arr[i] == nil {
			if firstNil == true {
				return false
			}
			firstNil = true
		}
	}
	return firstNil
}

func (p *PartyState) wrapError(err error, round int) error {
	return errors.Wrapf(err, "party %s, round %d", p.partyID, round)
}
