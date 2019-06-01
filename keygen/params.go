package keygen

import (
	"github.com/binance-chain/tss-lib/types"
)

type (
	KGParameters struct {
		p2pCtx          *types.PeerContext
		partyID         *types.PartyID
		partyCount      int
		threshold       int
		localShareCount int // partyCount - 1
	}
)

// Exported, used in `tss` client
func NewKGParameters(ctx *types.PeerContext, partyID *types.PartyID, partyCount, threshold int) *KGParameters {
	return &KGParameters{
		p2pCtx:          ctx,
		partyID:         partyID,
		partyCount:      partyCount,
		threshold:       threshold,
		localShareCount: partyCount - 1,
	}
}

func (params *KGParameters) Ctx() *types.PeerContext {
	return params.p2pCtx
}

func (params *KGParameters) PartyID() *types.PartyID {
	return params.partyID
}

func (params *KGParameters) PartyCount() int {
	return params.partyCount
}

func (params *KGParameters) Threshold() int {
	return params.threshold
}

func (params *KGParameters) LocalShareCount() int {
	return params.localShareCount
}
