package keygen

import (
	"fmt"
	"path/filepath"
	"runtime"
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
