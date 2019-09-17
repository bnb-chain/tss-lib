package tss

type (
	// Fields must be exported for json marshalling
	Parameters struct {
		X_partyID    *PartyID     `json:"id"`
		X_parties    *PeerContext `json:"parties"`
		X_partyCount int          `json:"party_count"`
		X_threshold  int          `json:"threshold"`
	}

	ReGroupParameters struct {
		*Parameters     `json:"base_params"`
		X_newParties    *PeerContext `json:"new_parties"`
		X_newPartyCount int          `json:"new_party_count"`
		X_newThreshold  int          `json:"new_threshold"`
	}
)

// Exported, used in `tss` client
func NewParameters(ctx *PeerContext, partyCount, threshold int) *Parameters {
	return &Parameters{
		X_parties:    ctx,
		X_partyID:    ctx.OurPartyID,
		X_partyCount: partyCount,
		X_threshold:  threshold,
	}
}

func (params *Parameters) Parties() *PeerContext {
	return params.X_parties
}

func (params *Parameters) PartyID() *PartyID {
	return params.X_partyID
}

func (params *Parameters) PartyCount() int {
	return params.X_partyCount
}

func (params *Parameters) Threshold() int {
	return params.X_threshold
}

// ----- //

// Exported, used in `tss` client
func NewReGroupParameters(ctx, newCtx *PeerContext, partyCount, threshold, newPartyCount, newThreshold int) *ReGroupParameters {
	params := NewParameters(ctx, partyCount, threshold)
	return &ReGroupParameters{
		Parameters:      params,
		X_newParties:    newCtx,
		X_newPartyCount: newPartyCount,
		X_newThreshold:  newThreshold,
	}
}

func (rgParams *ReGroupParameters) OldParties() *PeerContext {
	return rgParams.Parties() // wr use the original method for old parties
}

func (rgParams *ReGroupParameters) NewParties() *PeerContext {
	return rgParams.X_newParties
}

func (rgParams *ReGroupParameters) OldCommitteePartyID() *PartyID {
	return rgParams.X_parties.OurPartyID
}

func (rgParams *ReGroupParameters) NewCommitteePartyID() *PartyID {
	return rgParams.X_newParties.OurPartyID
}

func (rgParams *ReGroupParameters) NewPartyCount() int {
	return rgParams.X_newPartyCount
}

func (rgParams *ReGroupParameters) NewThreshold() int {
	return rgParams.X_newThreshold
}

func (rgParams *ReGroupParameters) IsOldCommittee() bool {
	return rgParams.OldCommitteePartyID() != nil
}

func (rgParams *ReGroupParameters) IsNewCommittee() bool {
	return rgParams.NewCommitteePartyID() != nil
}
