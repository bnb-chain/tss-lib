package signing

import (
	"encoding/gob"
)

func init() {
	gob.RegisterName("SignRound1MtAInitMessage", SignRound1MtAInitMessage{})
	gob.RegisterName("SignRound1CommitMessage", SignRound1CommitMessage{})
	gob.RegisterName("SignRound2MtAMidMessage", SignRound2MtAMidMessage{})
	gob.RegisterName("SignRound3Message", SignRound3Message{})
	gob.RegisterName("SignRound4DecommitMessage", SignRound4DecommitMessage{})
	gob.RegisterName("SignRound5CommitMessage", SignRound5CommitMessage{})
	gob.RegisterName("SignRound6DecommitMessage", SignRound6DecommitMessage{})
	gob.RegisterName("SignRound7CommitMessage", SignRound7CommitMessage{})
	gob.RegisterName("SignRound8DecommitMessage", SignRound8DecommitMessage{})
	gob.RegisterName("SignRound9SignatureMessage", SignRound9SignatureMessage{})
}
