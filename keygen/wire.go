package keygen

import (
	"bytes"
	"encoding/gob"
)

func init() {
	gob.RegisterName("KGPhase1CommitMessage",   KGPhase1CommitMessage{})
	gob.RegisterName("KGPhase2VssMessage",      KGPhase2VssMessage{})
	gob.RegisterName("KGPhase2DeCommitMessage", KGPhase2DeCommitMessage{})
	gob.RegisterName("KGPhase3ZKProofMessage",  KGPhase3ZKProofMessage{})
	gob.RegisterName("KGPhase3ZKUProofMessage", KGPhase3ZKUProofMessage{})
}

// ----- //

// Encode encodes the Message in `gob` format
func EncodeMsg(msg KGMessage) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(&msg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode decodes the Message from `gob` format
func DecodeMsg(data []byte) (KGMessage, error) {
	buf := bytes.NewBuffer(data)
	var msg KGMessage
	if err := gob.NewDecoder(buf).Decode(&msg); err != nil {
		return nil, err
	}
	return msg, nil
}
