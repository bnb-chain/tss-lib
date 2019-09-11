package signing

import (
	"encoding/gob"
)

func init() {
	gob.RegisterName("SignRound1Message1", SignRound1Message1{})
	gob.RegisterName("SignRound1Message2", SignRound1Message2{})
	gob.RegisterName("SignRound2Message", SignRound2Message{})
	gob.RegisterName("SignRound3Message", SignRound3Message{})
	gob.RegisterName("SignRound4Message", SignRound4Message{})
	gob.RegisterName("SignRound5Message", SignRound5Message{})
	gob.RegisterName("SignRound6Message", SignRound6Message{})
	gob.RegisterName("SignRound7Message", SignRound7Message{})
	gob.RegisterName("SignRound8Message", SignRound8Message{})
	gob.RegisterName("SignRound9Message", SignRound9Message{})
}
