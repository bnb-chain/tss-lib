package tss

type (
	PeerContext struct {
		PartyIDs   SortedPartyIDs `json:"parties"`
		OurPartyID *PartyID       `json:"our_party_id"`
	}
)

// Exported and used in client implementations.
func NewPeerContextFromUnSortedIDs(parties UnSortedPartyIDs, ourIDIndex int) *PeerContext {
	return NewPeerContextFromSortedIDs(SortPartyIDs(parties), parties[ourIDIndex])
}

// Exported and used in client implementations.
func NewPeerContextFromUnSortedIDsWithoutUs(parties UnSortedPartyIDs) *PeerContext {
	return NewPeerContextFromSortedIDs(SortPartyIDs(parties), nil)
}

// Exported and used in client implementations.
func NewPeerContextFromSortedIDs(parties SortedPartyIDs, ourPartyID *PartyID) *PeerContext {
	return &PeerContext{
		PartyIDs:   parties,
		OurPartyID: ourPartyID,
	}
}

func (ctx *PeerContext) IDs() SortedPartyIDs {
	return ctx.PartyIDs
}

func (ctx *PeerContext) OurID() *PartyID {
	return ctx.OurPartyID
}
