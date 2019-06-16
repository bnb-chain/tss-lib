package tss

import (
	"fmt"
)

type (
	Message interface {
		GetTo() *PartyID
		GetFrom() *PartyID
		GetType() string
		ValidateBasic() bool
		String() string
	}

	MessageMetadata struct {
		// if `To` is `nil`, the message should be broadcast to all parties.
		To,
		From *PartyID
		MsgType string
	}
)

func (mm MessageMetadata) GetTo() *PartyID {
	return mm.To
}

func (mm MessageMetadata) GetFrom() *PartyID {
	return mm.From
}

func (mm MessageMetadata) GetType() string {
	return mm.MsgType
}

func (mm MessageMetadata) String() string {
	toStr := "all"
	if mm.To != nil {
		toStr = mm.To.String()
	}
	return fmt.Sprintf("From: %s, To: %s, MsgType: %s", mm.From.String(), toStr, mm.MsgType)
}
