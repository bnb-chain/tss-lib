package tss

import (
	"github.com/binance-chain/tss-lib/crypto"
)

type (
	Parameters struct {
		partyID *PartyID
		parties *PeerContext
		partyCount,
		threshold int
	}

	ReGroupParameters struct {
		*Parameters
		newParties *PeerContext
		newPartyCount,
		newThreshold int
		bigXs []*crypto.ECPoint
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

// ----- //

// Exported, used in `tss` client
func NewReGroupParameters(ctx, newCtx *PeerContext, partyID *PartyID, partyCount, threshold, newPartyCount, newThreshold int, bigXs []*crypto.ECPoint) *ReGroupParameters {
	params := NewParameters(ctx, partyID, partyCount, threshold)
	return &ReGroupParameters{
		Parameters:    params,
		newParties:    newCtx,
		newPartyCount: newPartyCount,
		newThreshold:  newThreshold,
		bigXs:         bigXs,
	}
}

func (rgParams *ReGroupParameters) NewParties() *PeerContext {
	return rgParams.newParties
}

func (rgParams *ReGroupParameters) NewPartyCount() int {
	return rgParams.newPartyCount
}

func (rgParams *ReGroupParameters) NewThreshold() int {
	return rgParams.newThreshold
}

func (rgParams *ReGroupParameters) BigXs() []*crypto.ECPoint {
	return rgParams.bigXs
}

func (rgParams *ReGroupParameters) IsOldCommittee() bool {
	partyID := rgParams.partyID
	for _, Pj := range rgParams.parties.IDs() {
		if partyID.Key.Cmp(Pj.Key) == 0 {
			return true
		}
	}
	return false
}

func (rgParams *ReGroupParameters) IsNewCommittee() bool {
	partyID := rgParams.partyID
	for _, Pj := range rgParams.newParties.IDs() {
		if partyID.Key.Cmp(Pj.Key) == 0 {
			return true
		}
	}
	return false
}
