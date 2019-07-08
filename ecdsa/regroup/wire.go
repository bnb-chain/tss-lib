package regroup

import (
	"bytes"
	"encoding/gob"

	"github.com/binance-chain/tss-lib/tss"
)

func init() {
	gob.RegisterName("DGRound1OldCommitteeCommitMessage",   DGRound1OldCommitteeCommitMessage{})
}

// ----- //

// Encode encodes the Message in `gob` format
func EncodeMsg(msg tss.Message) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(&msg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode decodes the Message from `gob` format
func DecodeMsg(data []byte) (tss.Message, error) {
	buf := bytes.NewBuffer(data)
	var msg tss.Message
	if err := gob.NewDecoder(buf).Decode(&msg); err != nil {
		return nil, err
	}
	return msg, nil
}
