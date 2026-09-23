// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/tss"
)

// BuildLocalSaveDataSubset takes a roster straight from the caller and reads
// `id.Key`, a promoted field. It has no return channel and already panics with a
// named message for a roster entry it cannot resolve, so a roster entry it
// cannot read at all belongs in the same place -- rather than one expression
// later, as an unattributed nil dereference.
func TestBuildLocalSaveDataSubsetNamesARosterEntryWithNoContent(t *testing.T) {
	ids := tss.GenerateTestPartyIDs(2)
	var empty tss.PartyID
	assert.NoError(t, json.Unmarshal([]byte(`{"index":1}`), &empty))
	roster := tss.SortedPartyIDs{ids[0], &empty}

	source := NewLocalPartySaveData(2)
	for j, id := range ids {
		source.Ks[j] = id.KeyInt()
	}

	assert.PanicsWithError(t,
		"BuildLocalSaveDataSubset: a party in the given roster has no PartyID content",
		func() { BuildLocalSaveDataSubset(source, roster) },
		"the fault must name what is wrong with the input it was handed")
}

// Negative control: an ordinary roster must still build a subset, and the
// unresolvable-key path must still report its own reason rather than being
// absorbed by the new guard.
func TestBuildLocalSaveDataSubsetStillWorksAndStillReportsUnknownKeys(t *testing.T) {
	ids := tss.GenerateTestPartyIDs(2)
	source := NewLocalPartySaveData(2)
	for j, id := range ids {
		source.Ks[j] = id.KeyInt()
	}

	assert.NotPanics(t, func() {
		subset := BuildLocalSaveDataSubset(source, ids)
		assert.Len(t, subset.Ks, 2)
	})

	stranger := tss.GenerateTestPartyIDs(3)[2]
	assert.PanicsWithError(t,
		"BuildLocalSaveDataSubset: unable to find a signer party in the local save data",
		func() { BuildLocalSaveDataSubset(source, tss.SortedPartyIDs{ids[0], stranger}) })
}
