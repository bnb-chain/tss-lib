package types

import (
	"fmt"
)

type (
	Message interface {
		GetTo() *PartyID
		GetFrom() *PartyID
		GetType() string
	}

	MessageMetadata struct {
		// if `To` is `nil`, the message should be broadcast to all parties.
		To,
		From *PartyID
		MsgType string
	}
)

func (kgMM MessageMetadata) GetTo() *PartyID {
	return kgMM.To
}

func (kgMM MessageMetadata) GetFrom() *PartyID {
	return kgMM.From
}

func (kgMM MessageMetadata) GetType() string {
	return kgMM.MsgType
}

func (kgMM MessageMetadata) String() string {
	toStr := "all"
	if kgMM.To != nil {
		toStr = kgMM.To.String()
	}
	return fmt.Sprintf("From: %s, To: %s, MsgTpe: %s", kgMM.From.String(), toStr, kgMM.MsgType)
}
