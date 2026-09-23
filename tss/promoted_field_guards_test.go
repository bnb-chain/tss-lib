// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A PartyID whose outer pointer is non-nil but whose embedded
// *MessageWrapper_PartyID is nil is not a hypothetical shape: encoding/json
// produces it from any object without the embedded fields, and so does a
// shallow copy. Reading any promoted field then dereferences the nil.
func TestJSONProducesAPartyIDWithNoContent(t *testing.T) {
	var pid PartyID
	assert.NoError(t, json.Unmarshal([]byte(`{"index":3}`), &pid))
	assert.Nil(t, pid.MessageWrapper_PartyID,
		"this is the shape the guards below exist for")
	assert.Equal(t, 3, pid.Index)
}

// String is the one method that must never fault: it is what gets called while
// something is already being diagnosed. fmt recovers a panicking String and
// prints %!v(PANIC=...), so it is the DIRECT call that used to take the process
// with it -- and a direct call is what a log line assembling its own text does.
func TestStringAnswersForAPartyIDWithNoContent(t *testing.T) {
	var pid PartyID
	assert.NoError(t, json.Unmarshal([]byte(`{"index":3}`), &pid))

	assert.NotPanics(t, func() {
		s := pid.String()
		assert.Contains(t, s, "3", "the index is still known and still worth printing")
	}, "String must answer rather than fault")

	// Via fmt as well, where the answer must be the real one and not fmt's
	// recovered-panic placeholder.
	assert.NotContains(t, fmt.Sprintf("%v", pid), "PANIC")
}

// Negative control: an ordinary PartyID must print exactly what it printed
// before. Answering "no content" for everything would satisfy the test above.
func TestStringIsUnchangedForAnOrdinaryPartyID(t *testing.T) {
	ids := GenerateTestPartyIDs(2)
	pid := ids[1]
	assert.Equal(t, fmt.Sprintf("{%d,%s}", pid.Index, pid.Moniker), pid.String())
	assert.NotContains(t, pid.String(), "no PartyID content")
}
