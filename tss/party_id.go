// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/binance-chain/tss-lib/common"
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

// --- ProtoBuf Extensions

func (mpid *MessageWrapper_PartyID) KeyInt() *big.Int {
	return new(big.Int).SetBytes(mpid.Key)
}

// ----- //

// NewPartyID constructs a new PartyID
// Exported, used in `tss` client. `key` should remain consistent between runs for each party.
func NewPartyID(id string, moniker string, key *big.Int) *PartyID {
	return &PartyID{
		MessageWrapper_PartyID: &MessageWrapper_PartyID{
			Id:      id,
			Moniker: moniker,
			Key:     key.Bytes(),
		},
		Index: -1, // not known until sorted
	}
}

func (pid PartyID) String() string {
	return fmt.Sprintf("{%d,%s}", pid.Index, pid.Moniker)
}

// ----- //

// SortPartyIDs sorts a list of []*PartyID by their keys in ascending order
// Exported, used in `tss` client
func SortPartyIDs(ids UnSortedPartyIDs, startAt ...int) SortedPartyIDs {
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
	key := common.MustGetRandomInt(256)
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

func (spids SortedPartyIDs) Keys() []*big.Int {
	ids := make([]*big.Int, spids.Len())
	for i, pid := range spids {
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

func (spids SortedPartyIDs) Less(a, b int) bool {
	return spids[a].KeyInt().Cmp(spids[b].KeyInt()) <= 0
}

func (spids SortedPartyIDs) Swap(a, b int) {
	spids[a], spids[b] = spids[b], spids[a]
}
