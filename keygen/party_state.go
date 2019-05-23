package keygen

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/types"
)

type (
	PartyStateMonitor interface {
		NotifyPhase1Complete()
		NotifyPhase2Complete()
		NotifyPhase3Complete()
	}

	PartyState struct {
		partyID types.PartyID

		p2pCtx   *types.PeerContext
		kgParams KGParameters
		monitor  PartyStateMonitor

		isLocal  bool
		currentState string
		lastMessage  KGMessage

		kgPhase1CommitMessages   []*KGPhase1CommitMessage
		kgPhase2VssMessages      []*KGPhase2VssMessage
		kgPhase2DeCommitMessages []*KGPhase2DeCommitMessage
		kgPhase3ZKProofMessages  []*KGPhase3ZKProofMessage
		kgPhase3ZKUProofMessage  []*KGPhase3ZKUProofMessage
	}
)

func NewPartyState(
		p2pCtx *types.PeerContext, kgParams KGParameters, partyID types.PartyID, monitor PartyStateMonitor) *PartyState {
	partyCount := kgParams.partyCount
	return &PartyState{
		partyID:                  partyID,
		kgParams:                 kgParams,
		p2pCtx:                   p2pCtx,
		monitor:                  monitor,
		kgPhase1CommitMessages:   make([]*KGPhase1CommitMessage, partyCount),
		kgPhase2VssMessages:      make([]*KGPhase2VssMessage, partyCount),
		kgPhase2DeCommitMessages: make([]*KGPhase2DeCommitMessage, partyCount),
		kgPhase3ZKProofMessages:  make([]*KGPhase3ZKProofMessage, partyCount),
		kgPhase3ZKUProofMessage:  make([]*KGPhase3ZKUProofMessage, partyCount),
	}
}

func (p *PartyState) Update(msg KGMessage) (bool, error) {
	if msg == nil {
		panic(fmt.Errorf("nil message received by party %s", p.partyID))
	}
	p.lastMessage = msg // this is a pointer

	fmt.Printf("party %s received message: %s", p.partyID, msg.GetType())

	switch msg.(type) {
	case KGPhase1CommitMessage:
		if p.lastMessage != nil {
			return false, fmt.Errorf("unexpected state")
		}
		p.tryStartPhase2()
	default:
		panic(fmt.Errorf("unrecognised message: %v", msg))
	}

	return true, nil
}

func (p *PartyState) tryStartPhase2() {
	// guard - do we have the required number of messages?
	if !p.hasRequiredMessages(p.kgPhase1CommitMessages) {
		return
	}
	// vss generate
	if p.monitor != nil {
		p.monitor.NotifyPhase1Complete()
	}
}

func (p *PartyState) hasRequiredMessages(msgs interface{}) bool {
	arr, ok := msgs.([]interface{})
	if !ok {
		panic("messages could not be casted to an array")
	}
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

func (p *PartyState) wrapError(err error, phase int) error {
	return errors.Wrapf(err, "party %s, phase %d", p.partyID, phase)
}
