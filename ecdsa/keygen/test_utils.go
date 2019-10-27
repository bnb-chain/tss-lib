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
	"math/big"
	"path/filepath"
	"runtime"

	"github.com/pkg/errors"
)

const (
	// To change these parameters, you must first delete the text fixture files in test/_fixtures/ and then run the keygen test alone.
	// Then the signing and resharing tests will work with the new n, t configuration using the newly written fixture files.
	TestParticipants = 20
	TestThreshold    = TestParticipants / 2
)
const (
	testFixtureDirFormat  = "%s/../../test/_fixtures"
	testFixtureFileFormat = "keygen_data_%d.json"
)

func LoadKeygenTestFixtures(count int) ([]LocalPartySaveData, error) {
	keys := make([]LocalPartySaveData, 0, count)
	for j := 0; j < count; j++ {
		fixtureFilePath := makeTestFixtureFilePath(j)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				j, fixtureFilePath)
		}
		var key LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				j, fixtureFilePath)
		}
		keys = append(keys, LocalPartySaveData{
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
		})
	}
	return keys, nil
}

func LoadNTildeH1H2FromTestFixture(idx int) (NTildei, h1i, h2i *big.Int, err error) {
	fixtures, err := LoadKeygenTestFixtures(idx + 1)
	if err != nil {
		return
	}
	fixture := fixtures[idx]
	NTildei, h1i, h2i = fixture.NTildei, fixture.H1i, fixture.H2i
	return
}

func makeTestFixtureFilePath(partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}
