// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mobile

import (
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/gogo/protobuf/sortkeys"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants = 3
	testThreshold    = 2
)

func setupParams() (int, *tss.Parameters, []int64, error) {
	keys := make([]int64, 4)
	for i := range keys {
		keyBI := common.MustGetRandomInt(64)
		key := keyBI.Int64()
		keys[i] = key
	}
	paramsID := InitParamsBuilder("id_0", "moniker_0", keys[0], testParticipants, testThreshold)
	for i, key := range keys {
		if i == 0 {
			continue
		}
		n, err := AddPartyToParams(paramsID, fmt.Sprintf("id_%d", i), fmt.Sprintf("moniker_%d", i), key)
		if err != nil {
			return -1, nil, nil, err
		}
		if n != i+1 {
			panic(errors.New("expected n == i + 1 in loop"))
		}
	}
	params, err := getParams(paramsID)
	return paramsID, params, keys, err
}

func TestParamsBuilder(t *testing.T) {
	_, params, keys, err := setupParams()
	assert.NoError(t, err)
	assert.Equal(t, 4, len(params.Parties().IDs()))
	assert.Equal(t, keys[0], params.PartyID().Key.Int64())
	assert.Equal(t, params.PartyCount(), testParticipants)
	assert.Equal(t, params.Threshold(), testThreshold)
	assert.Equal(t, "id_0", params.PartyID().ID)
	assert.Equal(t, "moniker_0", params.PartyID().Moniker)
	keyI64s := make([]int64, 4)
	for i, partyID := range params.Parties().IDs() {
		keyI64s[i] = partyID.Key.Int64()
	}
	sort.Sort(sortkeys.Int64Slice(keyI64s))
	for i, partyID := range params.Parties().IDs() {
		assert.Equal(t, keyI64s[i], partyID.Key.Int64())
	}
}
