// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package eddsa

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"

	"github.com/bnb-chain/tss-lib/v2/mpc"
)

func loadKeyIndex(index int, total int) (*keygen.LocalPartySaveData, *tss.PartyID, error) {
	fixtureFilePath := mpc.GetKeyPath("eddsa", index)
	bz, err := ioutil.ReadFile(fixtureFilePath)
	if err != nil {
		return nil, nil, err
	}
	var key keygen.LocalPartySaveData
	if err = json.Unmarshal(bz, &key); err != nil {
		return nil, nil, err
	}
	for _, kbxj := range key.BigXj {
		kbxj.SetCurve(tss.Edwards())
	}
	key.EDDSAPub.SetCurve(tss.Edwards())
	partyID := mpc.MakeParty(index, total, key.ShareID)

	return &key, partyID, nil
}

func LoadKeys(indexes []int, total int) ([]*keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]*keygen.LocalPartySaveData, 0, len(indexes))
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	for _, index := range indexes {
		key, partyID, err := loadKeyIndex(index, total)
		if err != nil {
			return nil, nil, err
		}
		keys = append(keys, key)
		partyIDs = append(partyIDs, partyID)
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	return keys, sortedPIDs, nil
}

func SaveKey(index int, data *keygen.LocalPartySaveData) {
	fixtureFilePath := mpc.GetKeyPath("eddsa", index)
	fd, err := os.OpenFile(fixtureFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err.Error())
	}

	bz, err := json.MarshalIndent(&data, "", "  ")
	if err != nil {
		panic(err.Error())
	}

	_, err = fd.Write(bz)
	if err != nil {
		panic(err.Error())
	}
}
