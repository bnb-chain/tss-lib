// Copyright © 2026 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss_test

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/tss"
)

// ReSharingParameters embeds *Parameters, so OldParties / OldPartyCount /
// IsOldCommittee / IsNewCommittee read PROMOTED fields and methods. A zero
// value and a JSON round trip of "{}" both leave that pointer nil, and every
// promoted read then faults. NewParties / NewPartyCount / NewThreshold are
// fine because those are ReSharingParameters' own fields.
func nilEmbeddedCases(t *testing.T) map[string]*tss.ReSharingParameters {
	t.Helper()
	fromJSON := new(tss.ReSharingParameters)
	assert.NoError(t, json.Unmarshal([]byte("{}"), fromJSON))
	return map[string]*tss.ReSharingParameters{
		"zero value":     {},
		"json.Unmarshal": fromJSON,
		"new(T)":         new(tss.ReSharingParameters),
	}
}

func TestReSharingParametersTolerateNilEmbeddedParameters(t *testing.T) {
	for name, rgParams := range nilEmbeddedCases(t) {
		t.Run(name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				// An absent embedded *Parameters describes no old committee, so
				// the honest answer is the same one PeerContext.IDs gives for a
				// nil context: nobody.
				assert.Nil(t, rgParams.OldParties())
				assert.Empty(t, rgParams.OldParties().IDs())
				assert.Equal(t, 0, rgParams.OldPartyCount())
				assert.Empty(t, rgParams.OldAndNewParties())
				assert.Equal(t, 0, rgParams.OldAndNewPartyCount())
				// This party has no readable key, so it matches no roster --
				// the same answer isInCommittee already gives for a PartyID
				// with a nil embedded MessageWrapper_PartyID.
				assert.False(t, rgParams.IsOldCommittee())
				assert.False(t, rgParams.IsNewCommittee())
			})
		})
	}
}

// TestReSharingParametersUnchangedWhenParametersPresent is the negative
// control: for a properly constructed value every method must return exactly
// what it returned before the nil guards were added.
func TestReSharingParametersUnchangedWhenParametersPresent(t *testing.T) {
	ec := tss.S256()
	oldIDs := tss.SortPartyIDs([]*tss.PartyID{
		tss.NewPartyID("1", "P1", big.NewInt(11)),
		tss.NewPartyID("2", "P2", big.NewInt(22)),
	})
	newIDs := tss.SortPartyIDs([]*tss.PartyID{
		tss.NewPartyID("3", "P3", big.NewInt(33)),
		tss.NewPartyID("4", "P4", big.NewInt(44)),
		tss.NewPartyID("5", "P5", big.NewInt(55)),
	})
	oldCtx, newCtx := tss.NewPeerContext(oldIDs), tss.NewPeerContext(newIDs)

	self := oldIDs[0]
	rgParams := tss.NewReSharingParameters(ec, oldCtx, newCtx, self, 2, 1, 3, 2)

	assert.Same(t, oldCtx, rgParams.OldParties())
	assert.Same(t, oldCtx, rgParams.Parties())
	assert.Equal(t, 2, rgParams.OldPartyCount())
	assert.Same(t, newCtx, rgParams.NewParties())
	assert.Equal(t, 3, rgParams.NewPartyCount())
	assert.Equal(t, 5, rgParams.OldAndNewPartyCount())
	assert.Len(t, rgParams.OldAndNewParties(), 5)
	assert.True(t, rgParams.IsOldCommittee())
	assert.False(t, rgParams.IsNewCommittee())

	// And from the new committee's side.
	rgParamsNew := tss.NewReSharingParameters(ec, oldCtx, newCtx, newIDs[1], 2, 1, 3, 2)
	assert.False(t, rgParamsNew.IsOldCommittee())
	assert.True(t, rgParamsNew.IsNewCommittee())
}

// TestReSharingParametersNilRostersStillWork pins that the guards added for a
// nil embedded *Parameters did not disturb the already-tolerated case of a
// present *Parameters holding nil PeerContexts.
func TestReSharingParametersNilRostersStillWork(t *testing.T) {
	ec := tss.S256()
	self := tss.NewPartyID("1", "P1", big.NewInt(11))
	rgParams := tss.NewReSharingParameters(ec, nil, nil, self, 2, 1, 3, 2)
	assert.NotPanics(t, func() {
		assert.Empty(t, rgParams.OldParties().IDs())
		assert.Equal(t, 2, rgParams.OldPartyCount())
		assert.False(t, rgParams.IsOldCommittee())
		assert.False(t, rgParams.IsNewCommittee())
	})
}
