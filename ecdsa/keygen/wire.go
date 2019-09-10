package keygen

import (
	"bytes"
	"encoding/gob"

	"github.com/binance-chain/tss-lib/tss"
)

func init() {
	gob.RegisterName("KGRound1Message",   KGRound1Message{})
	gob.RegisterName("KGRound2Message1",      KGRound2Message1{})
	gob.RegisterName("KGRound2Message2", KGRound2Message2{})
	gob.RegisterName("KGRound3Message", KGRound3Message{})
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
