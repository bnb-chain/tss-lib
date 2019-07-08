package regroup

import (
	"github.com/ipfs/go-log"
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

// ----- //

// TODO implement tests
