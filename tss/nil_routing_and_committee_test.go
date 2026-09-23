// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"math/big"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func mkPID(name string, key int64, idx int) *PartyID {
	return &PartyID{
		MessageWrapper_PartyID: &MessageWrapper_PartyID{
			Id: name, Moniker: name, Key: big.NewInt(key).Bytes(),
		},
		Index: idx,
	}
}

func wantAttributablePanic(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected a panic mentioning %q", want)
		}
		err, ok := r.(error)
		if !ok {
			t.Fatalf("expected the panic value to be an error, got %T: %v", r, r)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("panicked, but not with the intended attributable error: %v", err)
		}
	}()
	fn()
}

// `routing.To != nil` guards the container; the elements reached through it are
// nil-able too.
func TestNewMessageWrapperGuardsTheElementNotJustTheContainer(t *testing.T) {
	from := mkPID("from", 1, 0)
	good := mkPID("to", 2, 1)

	wantAttributablePanic(t, "routing.To[1]", func() {
		NewMessageWrapper(MessageRouting{From: from, To: []*PartyID{good, nil}}, nil)
	})
	wantAttributablePanic(t, "routing.To[0]", func() {
		NewMessageWrapper(MessageRouting{From: from, To: []*PartyID{new(PartyID)}}, nil)
	})
	wantAttributablePanic(t, "routing.From", func() {
		NewMessageWrapper(MessageRouting{From: nil, To: []*PartyID{good}}, nil)
	})
	wantAttributablePanic(t, "routing.From", func() {
		NewMessageWrapper(MessageRouting{From: new(PartyID), To: []*PartyID{good}}, nil)
	})
}

// Negative control: well-formed routing must still build, including the
// broadcast case where To is nil by design.
func TestNewMessageWrapperStillBuildsWellFormedRouting(t *testing.T) {
	from, to := mkPID("from", 1, 0), mkPID("to", 2, 1)
	if w := NewMessageWrapper(MessageRouting{From: from, To: []*PartyID{to}}, nil); w == nil || len(w.To) != 1 {
		t.Fatal("point-to-point routing must still build")
	}
	if w := NewMessageWrapper(MessageRouting{From: from, To: nil, IsBroadcast: true}, nil); w == nil || w.To != nil {
		t.Fatal("broadcast routing (nil To) must still build")
	}
}

// NewParameters accepts a nil PeerContext and stores it unconditionally, and the
// resharing constructor calls IsOldCommittee before any round runs -- so
// BaseStart's validation is too late to protect this path.
func TestIsCommitteeIsNilSafe(t *testing.T) {
	self := mkPID("self", 7, 0)
	peer := mkPID("peer", 8, 1)
	newCtx := NewPeerContext(SortedPartyIDs{self, peer})
	other := NewPeerContext(SortedPartyIDs{mkPID("o1", 98, 0), mkPID("o2", 99, 1)})

	// NewParameters stores a nil PeerContext unconditionally.
	p := NewReSharingParameters(btcec.S256(), nil, newCtx, self, 2, 1, 2, 1)
	if p.IsOldCommittee() {
		t.Fatal("a nil old-committee context contains nobody")
	}
	if !p.IsNewCommittee() {
		t.Fatal("the new committee still contains this party")
	}

	// A malformed self PartyID matches nobody rather than faulting.
	p2 := NewReSharingParameters(btcec.S256(), newCtx, other, new(PartyID), 2, 1, 2, 1)
	if p2.IsOldCommittee() || p2.IsNewCommittee() {
		t.Fatal("a party with no readable key matches nobody")
	}

	// A malformed roster ENTRY is skipped, not faulted on.
	mixed := NewPeerContext(SortedPartyIDs{new(PartyID), self})
	p3 := NewReSharingParameters(btcec.S256(), mixed, other, self, 2, 1, 2, 1)
	if !p3.IsOldCommittee() {
		t.Fatal("the well-formed entry must still be found past the malformed one")
	}
}

func TestPeerContextIDsIsNilReceiverSafe(t *testing.T) {
	var nilCtx *PeerContext
	if ids := nilCtx.IDs(); ids != nil {
		t.Fatalf("a nil PeerContext yields no parties, got %v", ids)
	}
}
