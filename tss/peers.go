package tss

type (
	PeerContext struct {
		partyIDs SortedPartyIDs
	}
)

func NewPeerContext(parties SortedPartyIDs) *PeerContext {
	return &PeerContext{partyIDs: parties}
}

func (p2pCtx *PeerContext) IDs() SortedPartyIDs {
	return p2pCtx.partyIDs
}
