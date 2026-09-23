// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// A PartyID whose outer pointer is non-nil while the embedded
// *MessageWrapper_PartyID is nil is exactly what encoding/json produces from
// `{"index":n}`. Build it that way rather than by hand, so the test keeps
// testing a shape a caller can actually produce.
func nilEmbeddedPartyID(t *testing.T) *PartyID {
	t.Helper()
	pid := new(PartyID)
	if err := json.Unmarshal([]byte(`{"index":0}`), pid); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pid.MessageWrapper_PartyID != nil {
		t.Fatalf("fixture is wrong: embedded pointer is not nil, so this test would prove nothing")
	}
	return pid
}

// SortPartyIDs means to reject this shape. It has to reject it by its own
// panic, not by faulting inside the guard: `id.KeyInt() == nil` would
// dereference the nil embedded pointer while evaluating the condition.
func TestSortPartyIDsRejectsNilEmbeddedWithItsOwnPanic(t *testing.T) {
	ids := UnSortedPartyIDs{nilEmbeddedPartyID(t)}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected a panic")
		}
		err, ok := r.(error)
		if !ok {
			t.Fatalf("expected the panic value to be an error, got %T: %v", r, r)
		}
		if !strings.Contains(err.Error(), "SortPartyIDs:") {
			t.Fatalf("panicked, but not with the intended attributable error: %v", err)
		}
	}()

	SortPartyIDs(ids)
}

// The same shape reaching assertDistinctIDsModQ through the exported
// constructor. The guard there skips rather than rejects, matching partyKeyID;
// what it must not do is fault.
func TestNewParametersSkipsNilEmbeddedInsteadOfFaulting(t *testing.T) {
	good := &PartyID{
		MessageWrapper_PartyID: &MessageWrapper_PartyID{
			Id: "good", Moniker: "good", Key: big.NewInt(7).Bytes(),
		},
		Index: 0,
	}
	bad := nilEmbeddedPartyID(t)
	bad.Index = 1

	ctx := NewPeerContext(SortedPartyIDs{good, bad})
	params := NewParameters(btcec.S256(), ctx, good, 2, 1)
	if params == nil {
		t.Fatal("NewParameters returned nil")
	}
}

// Keys() is reachable without going through SortPartyIDs: SortedPartyIDs is an
// exported slice type and NewPeerContext takes one as-is.
func TestSortedPartyIDsKeysRejectsNilEmbeddedWithItsOwnPanic(t *testing.T) {
	spids := SortedPartyIDs{nilEmbeddedPartyID(t)}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected a panic")
		}
		err, ok := r.(error)
		if !ok {
			t.Fatalf("expected the panic value to be an error, got %T: %v", r, r)
		}
		if !strings.Contains(err.Error(), "SortedPartyIDs.Keys:") {
			t.Fatalf("panicked, but not with the intended attributable error: %v", err)
		}
	}()

	spids.Keys()
}

// Keys() must still return the keys for well-formed input, or the test above
// would pass against a Keys() that panicked unconditionally.
func TestSortedPartyIDsKeysStillReturnsKeys(t *testing.T) {
	mk := func(name string, key int64, idx int) *PartyID {
		return &PartyID{
			MessageWrapper_PartyID: &MessageWrapper_PartyID{
				Id: name, Moniker: name, Key: big.NewInt(key).Bytes(),
			},
			Index: idx,
		}
	}
	got := SortedPartyIDs{mk("a", 7, 0), mk("b", 9, 1)}.Keys()
	if len(got) != 2 || got[0].Int64() != 7 || got[1].Int64() != 9 {
		t.Fatalf("got %v, want [7 9]", got)
	}
}

// The distinctness check must still fire for well-formed IDs, or the test above
// would pass just as well against a guard that skipped everything.
func TestNewParametersStillRejectsCollidingKeys(t *testing.T) {
	mk := func(name string, key *big.Int, idx int) *PartyID {
		return &PartyID{
			MessageWrapper_PartyID: &MessageWrapper_PartyID{
				Id: name, Moniker: name, Key: key.Bytes(),
			},
			Index: idx,
		}
	}
	q := btcec.S256().Params().N
	a := mk("a", big.NewInt(7), 0)
	b := mk("b", new(big.Int).Add(q, big.NewInt(7)), 1) // same residue mod q

	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for mod-q colliding keys; the guard change must not have disarmed it")
		}
	}()

	ctx := NewPeerContext(SortedPartyIDs{a, b})
	NewParameters(btcec.S256(), ctx, a, 2, 1)
}
