package tss

type (
	Parameters struct {
		partyID    *PartyID
		parties    *PeerContext
		partyCount int
		threshold  int
	}
)

// Exported, used in `tss` client
func NewParameters(ctx *PeerContext, partyID *PartyID, partyCount, threshold int) *Parameters {
	return &Parameters{
		parties:    ctx,
		partyID:    partyID,
		partyCount: partyCount,
		threshold:  threshold,
	}
}

func (params *Parameters) Parties() *PeerContext {
	return params.parties
}

func (params *Parameters) PartyID() *PartyID {
	return params.partyID
}

func (params *Parameters) PartyCount() int {
	return params.partyCount
}

func (params *Parameters) Threshold() int {
	return params.threshold
}
