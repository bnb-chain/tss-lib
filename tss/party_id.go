package tss

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/binance-chain/tss-lib/common/random"
)

type (
	PartyID struct {
		Moniker string   `json:"moniker"`
		Key     *big.Int `json:"key"` // used in crypto and for sorting parties
		Index   int      `json:"index"`
	}

	UnSortedPartyIDs []*PartyID
	SortedPartyIDs   []*PartyID
)

// ----- //

// Exported and used in client implementations.
// `key` should remain consistent between runs for each party.
func NewPartyID(moniker string, key *big.Int) *PartyID {
	return &PartyID{
		Moniker: moniker,
		Key:     key,
		Index:   -1, // not known until sorted
	}
}

func (pid PartyID) String() string {
	return fmt.Sprintf("{%d,%s}", pid.Index, pid.Moniker)
}

// ----- //

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

func GenerateTestPartyIDs(count int, startAt ...int) SortedPartyIDs {
	ids := make(UnSortedPartyIDs, 0, count)
	key := random.MustGetRandomInt(256)
	frm := 0
	i := 0 // default `i`
	if len(startAt) > 0 {
		frm = startAt[0]
		i = startAt[0]
	}
	for ; i < count+frm; i++ {
		ids = append(ids, &PartyID{
			Moniker: fmt.Sprintf("P[%d]", i+1),
			Key:     new(big.Int).Sub(key, big.NewInt(int64(count)-int64(i))),
			Index:   i,
			// this key makes tests more deterministic
		})
	}
	return SortPartyIDs(ids, startAt...)
}

func (spids SortedPartyIDs) Keys() []*big.Int {
	ids := make([]*big.Int, spids.Len())
	for i, pid := range spids {
		ids[i] = pid.Key
	}
	return ids
}

func (spids SortedPartyIDs) ToUnSorted() UnSortedPartyIDs {
	return UnSortedPartyIDs(spids)
}

func (spids SortedPartyIDs) FindByKey(key *big.Int) *PartyID {
	for _, pid := range spids {
		if pid.Key.Cmp(key) == 0 {
			return pid
		}
	}
	return nil
}

func (spids SortedPartyIDs) Exclude(exclude *PartyID) SortedPartyIDs {
	newSpIDs := make(SortedPartyIDs, 0, len(spids))
	for _, pid := range spids {
		if pid.Key.Cmp(exclude.Key) == 0 {
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
	return spids[a].Key.Cmp(spids[b].Key) <= 0
}

func (spids SortedPartyIDs) Swap(a, b int) {
	spids[a], spids[b] = spids[b], spids[a]
}
