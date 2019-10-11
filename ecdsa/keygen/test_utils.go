// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"

	"github.com/pkg/errors"
)

const (
	testFixtureFileFormat = "keygen_data_%d.json"
)

func MakeTestFixtureFilePath(partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf("%s/../../test/_fixtures", srcDirName)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}

func LoadKeygenTestFixtures(count int) ([]LocalPartySaveData, error) {
	keys := make([]LocalPartySaveData, count, count)
	for j := 0; j < count; j++ {
		fixtureFilePath := MakeTestFixtureFilePath(j)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				j, fixtureFilePath)
		}
		var key LocalPartySaveData
		err = json.Unmarshal(bz, &key)

		if err != nil {
			return nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				j, fixtureFilePath)
		}
		keys[j] = LocalPartySaveData{
			LocalPreParams: LocalPreParams{
				PaillierSK: key.PaillierSK,
				NTildei:    key.NTildei,
				H1i:        key.H1i,
				H2i:        key.H2i,
			},
			LocalSecrets: LocalSecrets{
				Xi:      key.Xi,
				ShareID: key.ShareID,
			},
			Ks:          key.Ks[:count],
			NTildej:     key.NTildej[:count],
			H1j:         key.H1j[:count],
			H2j:         key.H2j[:count],
			BigXj:       key.BigXj[:count],
			PaillierPKs: key.PaillierPKs[:count],
			ECDSAPub:    key.ECDSAPub,
		}
	}
	return keys, nil
}
