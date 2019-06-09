package keygen

import (
	"bytes"
	"encoding/gob"

	"github.com/binance-chain/tss-lib/types"
)

func init() {
	gob.Register(KGRound1CommitMessage{})
	gob.Register(KGRound2VssMessage{})
	gob.Register(KGRound2DeCommitMessage{})
	gob.Register(KGRound3ZKUProofMessage{})
}

// ----- //

// Encode encodes the Message in `gob` format
func EncodeMsg(msg types.Message) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(&msg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode decodes the Message from `gob` format
func DecodeMsg(data []byte) (types.Message, error) {
	buf := bytes.NewBuffer(data)
	var msg types.Message
	if err := gob.NewDecoder(buf).Decode(&msg); err != nil {
		return nil, err
	}
	return msg, nil
}
