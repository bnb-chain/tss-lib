package keygen

import "fmt"

type (
	PartyStateMonitor interface {
		NotifyPhase1Complete()
		NotifyPhase2Complete()
		NotifyPhase3Complete()
	}

	PartyID struct {
		partyIdx uint8
		partyID  string
	}

	PartyState struct {
		partyID      *PartyID

		kgParams KGParameters
		isLocal  bool
		monitor  PartyStateMonitor

		currentState string
		lastMessage  *KGMessage

		kgPhase1CommitMessages   []*KGPhase1CommitMessage
		kgPhase2VssMessages      []*KGPhase2VssMessage
		kgPhase2DeCommitMessages []*KGPhase2DeCommitMessage
		kgPhase3ZKProofMessages  []*KGPhase3ZKProofMessage
		kgPhase3ZKUProofMessage  []*KGPhase3ZKUProofMessage
	}
)

func NewPartyState(kgParams KGParameters, partyID *PartyID, monitor PartyStateMonitor) *PartyState {
	partyCount := kgParams.PartyCount
	return &PartyState{
		partyID:                  partyID,
		kgParams:                 kgParams,
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
		panic("nil message received by party " + string(p.partyID.partyIdx))
	}
	p.lastMessage = &msg

	fmt.Printf("party %d:\treceived message %v", p.partyID.partyIdx, msg)

	switch msg.(type) {
	case KGPhase1CommitMessage:
		if p.lastMessage != nil {
			return false, fmt.Errorf("unexpected state")
		}
		p.tryStartPhase2()
	default:
		panic(fmt.Sprintf("unrecognised message: %v", msg))
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
