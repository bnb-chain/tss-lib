// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

type (
	PeerContext struct {
		partyIDs SortedPartyIDs
	}
)

func NewPeerContext(parties SortedPartyIDs) *PeerContext {
	return &PeerContext{partyIDs: parties}
}

// IDs returns the roster. A nil PeerContext yields no parties rather than
// faulting: NewParameters accepts a nil context and stores it unconditionally,
// and the library's own convention (see CommitteeOverlapKeys) is that a caller
// who passed nil has not described a committee. Every reader of this method
// ranges over the result, and ranging over nil is a no-op, so the nil case
// needs no special handling anywhere upstream.
func (p2pCtx *PeerContext) IDs() SortedPartyIDs {
	if p2pCtx == nil {
		return nil
	}
	return p2pCtx.partyIDs
}

func (p2pCtx *PeerContext) SetIDs(ids SortedPartyIDs) {
	p2pCtx.partyIDs = ids
}
