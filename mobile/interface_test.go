// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mobile

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants = 3
	testThreshold    = 2
)

var (
	cachedPreParams []byte
)

func setupPreParams(timeout time.Duration) (jsonPreParams []byte, err error) {
	if cachedPreParams == nil {
		cachedPreParams, err = GeneratePreParams(int64(timeout))
		if err != nil {
			return
		}
	}
	jsonPreParams = cachedPreParams
	return
}

func setupParams(pax int) (paramsID int, params *tss.Parameters, keys []int64, sortedKeys []int64, err error) {
	keys = make([]int64, pax)
	sortedKeys = make([]int64, pax)

	for i := range keys {
		keyBI := common.MustGetRandomInt(63) // w/o sign bit
		key := keyBI.Int64()
		keys[i] = key
	}

	paramsID = InitParamsBuilder("id_0", "moniker_0", keys[0], testParticipants, testThreshold)
	for j, key := range keys {
		if j == 0 {
			continue
		}
		if _, err := AddPartyToParams(paramsID, fmt.Sprintf("id_%d", j), fmt.Sprintf("moniker_%d", j), key); err != nil {
			return -1, nil, nil, nil, err
		}
	}
	params, err = getParams(paramsID)
	if err != nil {
		return -1, nil, nil, nil, err
	}

	for i, partyID := range params.Parties().IDs() {
		sortedKeys[i] = partyID.KeyInt().Int64()
	}
	sort.Slice(sortedKeys, func(i, j int) bool { return sortedKeys[i] < sortedKeys[j] })
	return
}

func TestParamsBuilder(t *testing.T) {
	_, params, keys, sortedKeys, err := setupParams(3)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(params.Parties().IDs()))
	assert.Equal(t, keys[0], params.PartyID().KeyInt().Int64())
	assert.Equal(t, params.PartyCount(), testParticipants)
	assert.Equal(t, params.Threshold(), testThreshold)
	assert.Equal(t, "id_0", params.PartyID().Id)
	assert.Equal(t, "moniker_0", params.PartyID().Moniker)
	for i, partyID := range params.Parties().IDs() {
		assert.Equal(t, sortedKeys[i], partyID.KeyInt().Int64())
	}
}

func TestGeneratePreParams_Timeout(t *testing.T) {
	_, err := GeneratePreParams(int64(0))
	assert.Error(t, err)
}

func TestKeygenSession(t *testing.T) {
	paramsID, _, _, _, err := setupParams(3)
	if !assert.NoError(t, err) {
		return
	}
	jsonPreParams, err := setupPreParams(5 * time.Minute)
	if !assert.NoError(t, err) {
		return
	}
	sessionID, err := InitKeygenSession(paramsID, AlgorithmECDSA, jsonPreParams)
	if !assert.NoError(t, err) {
		return
	}
	msg1, err := PollKeygenOrReSharingSession(sessionID)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotEmpty(t, msg1)
}

func TestSigningSession(t *testing.T) {
	paramsID, _, _, _, err := setupParams(3)
	if !assert.NoError(t, err) {
		return
	}
	keyData, err := keygen.LoadKeygenTestFixtures(3)
	if !assert.NoError(t, err) {
		return
	}
	jsonKeyData, err := json.Marshal(&keyData[0])
	if !assert.NoError(t, err) {
		return
	}
	msg := common.SHA512_256i(big.NewInt(42)).Bytes()
	sessionID, err := InitSigningSession(paramsID, AlgorithmECDSA, msg, jsonKeyData)
	if !assert.NoError(t, err) {
		return
	}
	msg1, err := PollSigningSession(sessionID)
	if !assert.NoError(t, err) {
		return
	}
	assert.NotEmpty(t, msg1)
}

func TestSigningSession_FailSmallKs(t *testing.T) {
	paramsID, _, _, _, err := setupParams(3)
	if !assert.NoError(t, err) {
		return
	}
	keyData, err := keygen.LoadKeygenTestFixtures(2)
	if !assert.NoError(t, err) {
		return
	}
	jsonKeyData, err := json.Marshal(&keyData[0])
	if !assert.NoError(t, err) {
		return
	}
	msg := common.SHA512_256i(big.NewInt(42)).Bytes()
	_, err = InitSigningSession(paramsID, AlgorithmECDSA, msg, jsonKeyData)
	if !assert.Error(t, err) {
		return
	}
}
