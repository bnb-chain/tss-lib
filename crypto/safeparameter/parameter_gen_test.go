// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package safeparameter

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ipfs/go-log"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
)

const (
	testFixtureDirFormat  = "%s/../../test/_ecdsa_fixtures"
	testFixtureFileFormat = "localParams_data_%d.json"
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func makeTestFixtureFilePath(partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}

func tryWriteTestFixtureFile(t *testing.T, index int, data LocalPreParams) {
	fixtureFileName := makeTestFixtureFilePath(index)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			t.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		t.Logf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}

func LoadPreParameter(qty int, optionalStart ...int) ([]LocalPreParams, error) {
	preParameters := make([]LocalPreParams, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	for i := start; i < qty; i++ {
		fixtureFilePath := makeTestFixtureFilePath(i)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var el LocalPreParams
		if err = json.Unmarshal(bz, &el); err != nil {
			return nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		preParameters = append(preParameters, el)
	}

	return preParameters, nil
}

func TestGenSafePaiBlumPrime(t *testing.T) {
	setUp("debug")
	ret, err := GeneratePaiBlumPreParams(time.Minute*5, runtime.NumCPU())
	assert.Nil(t, err)
	tryWriteTestFixtureFile(t, 0, *ret)
}

func TestPaiBlumPrimeProof(t *testing.T) {
	setUp("debug")
	allPreParameters, err := LoadPreParameter(2)
	assert.Nil(t, err)
	validParameter := allPreParameters[0]
	invalidParameter := allPreParameters[1]

	var challenges []*big.Int
	for i := 0; i < Iterations; i++ {
		var yi *big.Int
		eHash := common.SHA512_256i(validParameter.NTildei, validParameter.H2i, big.NewInt(int64(i)))
		yi = common.RejectionSample(validParameter.NTildei, eHash)
		challenges = append(challenges, yi)
	}

	omega := GenOmega(validParameter.NTildei)
	proof, err := ProvePaiBlumPreParams(challenges, omega, validParameter)
	assert.Nil(t, err)

	ret := proof.Verify(challenges, omega, validParameter.NTildei)
	assert.True(t, ret)

	// we test that if parameters are not paillier-blume integer, it cannot generate the valid proof
	_, err = ProvePaiBlumPreParams(challenges, omega, invalidParameter)
	assert.NotNil(t, err)
}

func TestGenChallenges(t *testing.T) {
	allPreParameters, err := LoadPreParameter(2)
	assert.Nil(t, err)
	validParameter := allPreParameters[0]
	omegas := make([]*big.Int, Iterations)
	for i := 0; i < Iterations; i++ {
		omegas[i] = GenOmega(validParameter.NTildei)
	}
	_, err = GenChallenges(validParameter.NTildei, omegas)
	assert.Nil(t, err)
	_, err = GenChallenges(nil, omegas)
	assert.NotNil(t, err)
}
