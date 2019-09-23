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
			key.Xi,
			key.ShareID,
			key.PaillierSk,
			key.BigXj[:count],
			key.PaillierPks[:count],
			key.NTildej[:count],
			key.H1j[:count],
			key.H2j[:count],
			key.Ks[:count],
			key.ECDSAPub,
		}
	}
	return keys, nil
}
