package types

import (
	"math/big"
	"sort"
)

type SortableIDs []*big.Int

func (s SortableIDs) Len() int {
	return len(s)
}

func (s SortableIDs) Less(i, j int) bool {
	return s[i].Cmp(s[j]) <= 0
}

func (s SortableIDs) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func GetPartyIDs(ids []*big.Int) SortableIDs {
	sorted := make(SortableIDs, 0, len(ids))
	for _, v := range ids {
		sorted = append(sorted, v)
	}
	sort.Sort(sorted)
	return sorted
}
