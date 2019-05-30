package types

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/binance-chain/tss-lib/crypto/hash"
)

type (
	PartyID struct {
		ID      string
		Moniker string
		Index   int
		Key     *big.Int // used in crypto and for sorting parties
	}

	UnSortedPartyIDs []*PartyID
	SortedPartyIDs   []*PartyID
)

// ----- //

// Exported, used in `tss` client
func NewPartyID(id string, moniker string) *PartyID {
	return &PartyID{
		Index:   -1, // not known until sorted
		ID:      id,
		Moniker: moniker,
		Key:     hash.StrHash(id),
	}
}

func (pid PartyID) String() string {
	return fmt.Sprintf("{%d,%s}", pid.Index, pid.Moniker)
}

// ----- //

// Exported, used in `tss` client
func SortPartyIDs(ids UnSortedPartyIDs) SortedPartyIDs {
	sorted := make(SortedPartyIDs, 0, len(ids))
	for _, id := range ids {
		sorted = append(sorted, id)
	}
	sort.Sort(sorted)
	// assign party indexes
	for i, id := range sorted {
		id.Index = i
	}
	return sorted
}

func (spids SortedPartyIDs) Keys() []*big.Int {
	ids := make([]*big.Int, spids.Len())
	for i, pid := range spids {
		ids[i] = pid.Key
	}
	return ids
}

func (spids SortedPartyIDs) FindByKey(key *big.Int) *PartyID {
	for _, pid := range spids {
		if pid.Key.Cmp(key) == 0 {
			return pid
		}
	}
	return nil
}

func (spids SortedPartyIDs) Len() int {
	return len(spids)
}

func (spids SortedPartyIDs) Less(a, b int) bool {
	return spids[a].Key.Cmp(spids[b].Key) <= 0
}

func (spids SortedPartyIDs) Swap(a, b int) {
	spids[a], spids[b] = spids[b], spids[a]
}
