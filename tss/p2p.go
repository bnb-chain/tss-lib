package tss

type (
	PeerContext struct {
		parties SortedPartyIDs
	}
)

func NewPeerContext(parties SortedPartyIDs) *PeerContext {
	return &PeerContext{parties: parties}
}

func (p2pCtx *PeerContext) Parties() SortedPartyIDs {
	return p2pCtx.parties
}
