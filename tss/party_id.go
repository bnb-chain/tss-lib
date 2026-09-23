// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"

	"github.com/bnb-chain/tss-lib/v4/common"
)

type (
	// PartyID represents a participant in the TSS protocol rounds.
	// Note: The `id` and `moniker` are provided for convenience to allow you to track participants easier.
	// The `id` is intended to be a unique string representation of `key` and `moniker` can be anything (even left blank).
	PartyID struct {
		*MessageWrapper_PartyID
		Index int `json:"index"`
	}

	UnSortedPartyIDs []*PartyID
	SortedPartyIDs   []*PartyID
)

// ValidateBasic reports whether this PartyID is well formed.
//
// The `pid != nil` conjunct guards only the OUTER pointer. `pid.Key` is a
// PROMOTED field: it compiles to `pid.MessageWrapper_PartyID.Key`, so reading
// it also dereferences the embedded pointer. A PartyID whose outer pointer is
// non-nil but whose embedded *MessageWrapper_PartyID is nil — the shape that
// encoding/json produces from `{"index":n}`, and that a shallow copy can
// produce — therefore used to fault inside the very predicate that is supposed
// to reject it. Test the embedded pointer explicitly, before the promoted read.
func (pid *PartyID) ValidateBasic() bool {
	return pid != nil && pid.MessageWrapper_PartyID != nil && pid.Key != nil && 0 <= pid.Index
}

// --- ProtoBuf Extensions

func (mpid *MessageWrapper_PartyID) KeyInt() *big.Int {
	return new(big.Int).SetBytes(mpid.Key)
}

// ----- //

// NewPartyID constructs a new PartyID
// Exported, used in `tss` client. `key` should remain consistent between runs for each party.
func NewPartyID(id, moniker string, key *big.Int) *PartyID {
	return &PartyID{
		MessageWrapper_PartyID: &MessageWrapper_PartyID{
			Id:      id,
			Moniker: moniker,
			Key:     key.Bytes(),
		},
		Index: -1, // not known until sorted
	}
}

// String is the one method on this type that must never fault. `pid.Moniker` is
// a PROMOTED field, so reading it dereferences the embedded pointer, and the
// PartyID shapes that encoding/json and a shallow copy produce leave that
// pointer nil. A diagnostic that panics while something is being diagnosed
// removes the diagnosis; note that a direct call is what faults, since fmt
// recovers a panicking String method and prints %!v(PANIC=...) instead.
//
// It answers with a marker rather than attributing a panic — the opposite of
// what crypto.ECPoint.X() does — because there is no return channel here and
// nothing downstream branches on the text.
func (pid PartyID) String() string {
	if pid.MessageWrapper_PartyID == nil {
		return fmt.Sprintf("{%d,<no PartyID content>}", pid.Index)
	}
	return fmt.Sprintf("{%d,%s}", pid.Index, pid.Moniker)
}

// ----- //

// SortPartyIDs sorts a list of []*PartyID by their keys in ascending order
// Exported, used in `tss` client. Panics if two parties share the same key
// — the Schnorr / range-proof session-binding scheme assumes pairwise-distinct
// keys, and a duplicate would compromise the sort.Interface contract.
func SortPartyIDs(ids UnSortedPartyIDs, startAt ...int) SortedPartyIDs {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		// `id.KeyInt() == nil` looks like the right test and is two things wrong.
		// KeyInt is promoted through the embedded *MessageWrapper_PartyID, so
		// evaluating it faults on precisely the malformed PartyID this line means
		// to reject -- turning an intended, attributable panic into a raw nil
		// dereference. And it can never be true anyway: KeyInt is
		// `new(big.Int).SetBytes(mpid.Key)`, and SetBytes(nil) yields 0, not nil.
		// Test the embedded pointer, the same way ValidateBasic does.
		if id == nil || id.MessageWrapper_PartyID == nil {
			panic(fmt.Errorf("SortPartyIDs: nil PartyID or nil embedded PartyID"))
		}
		keyHex := id.KeyInt().Text(16)
		if _, exists := seen[keyHex]; exists {
			panic(fmt.Errorf("SortPartyIDs: duplicate party key detected: %s", keyHex))
		}
		seen[keyHex] = struct{}{}
	}
	sorted := make(SortedPartyIDs, 0, len(ids))
	for _, id := range ids {
		sorted = append(sorted, id)
	}
	sort.Sort(sorted)
	// assign party indexes
	for i, id := range sorted {
		frm := 0
		if len(startAt) > 0 {
			frm = startAt[0]
		}
		id.Index = i + frm
	}
	return sorted
}

// GenerateTestPartyIDs generates a list of mock PartyIDs for tests
func GenerateTestPartyIDs(count int, startAt ...int) SortedPartyIDs {
	ids := make(UnSortedPartyIDs, 0, count)
	key := common.MustGetRandomInt(rand.Reader, 256)
	frm := 0
	i := 0 // default `i`
	if len(startAt) > 0 {
		frm = startAt[0]
		i = startAt[0]
	}
	for ; i < count+frm; i++ {
		ids = append(ids, &PartyID{
			MessageWrapper_PartyID: &MessageWrapper_PartyID{
				Id:      fmt.Sprintf("%d", i+1),
				Moniker: fmt.Sprintf("P[%d]", i+1),
				Key:     new(big.Int).Sub(key, big.NewInt(int64(count)-int64(i))).Bytes(),
			},
			Index: i,
			// this key makes tests more deterministic
		})
	}
	return SortPartyIDs(ids, startAt...)
}

// Keys returns each party's key as a *big.Int, in sorted order.
//
// It panics on a malformed entry rather than substituting a value. There is no
// safe substitute: the slice is positional, so a placeholder would have to be a
// number, and 0 is the one value that must never appear here — a party whose key
// is 0 mod q would receive the Shamir secret itself as its share. An
// attributable panic is the only honest outcome.
//
// SortedPartyIDs is an exported slice type, so it can be built directly (and
// NewPeerContext accepts one as-is), which is why this cannot rely on
// SortPartyIDs having screened the entries.
func (spids SortedPartyIDs) Keys() []*big.Int {
	ids := make([]*big.Int, spids.Len())
	for i, pid := range spids {
		// Test the embedded pointer: KeyInt is promoted through it, so reading
		// the key is what faults. See SortPartyIDs for the full reasoning.
		if pid == nil || pid.MessageWrapper_PartyID == nil {
			panic(fmt.Errorf("SortedPartyIDs.Keys: entry %d is a nil PartyID or has a nil embedded PartyID", i))
		}
		ids[i] = pid.KeyInt()
	}
	return ids
}

func (spids SortedPartyIDs) ToUnSorted() UnSortedPartyIDs {
	return UnSortedPartyIDs(spids)
}

func (spids SortedPartyIDs) FindByKey(key *big.Int) *PartyID {
	for _, pid := range spids {
		if pid.KeyInt().Cmp(key) == 0 {
			return pid
		}
	}
	return nil
}

func (spids SortedPartyIDs) Exclude(exclude *PartyID) SortedPartyIDs {
	newSpIDs := make(SortedPartyIDs, 0, len(spids))
	for _, pid := range spids {
		if pid.KeyInt().Cmp(exclude.KeyInt()) == 0 {
			continue // exclude
		}
		newSpIDs = append(newSpIDs, pid)
	}
	return newSpIDs
}

// Sortable

func (spids SortedPartyIDs) Len() int {
	return len(spids)
}

// Less reports whether party a should sort before party b. The comparator
// uses strict less-than to satisfy Go's sort.Interface strict-weak-ordering
// contract.
func (spids SortedPartyIDs) Less(a, b int) bool {
	return spids[a].KeyInt().Cmp(spids[b].KeyInt()) < 0
}

func (spids SortedPartyIDs) Swap(a, b int) {
	spids[a], spids[b] = spids[b], spids[a]
}
