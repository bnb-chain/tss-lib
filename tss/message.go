package tss

import (
	"fmt"

	"github.com/golang/protobuf/proto"
)

type (
	MessageMetadata struct {
		// if `To` is `nil` the message should be broadcast to all parties
		To             []*PartyID
		From           *PartyID
		MsgType        string
		ToOldCommittee bool // only `true` in DGRound2NewCommitteeACKMessage (regroup)
	}

	Message struct {
		MessageMetadata
		Msg proto.Message
	}
)

func (mm Message) GetTo() []*PartyID {
	return mm.To
}

func (mm Message) GetFrom() *PartyID {
	return mm.From
}

func (mm Message) GetType() string {
	return mm.MsgType
}

func (mm Message) GetMessage() proto.Message {
	return mm.Msg
}

func (mm Message) IsBroadcast() bool {
	return mm.To == nil || len(mm.To) > 1
}

func (mm Message) IsToOldCommittee() bool {
	return mm.ToOldCommittee
}

func (mm Message) String() string {
	toStr := "all"
	if mm.To != nil {
		toStr = fmt.Sprintf("%v", mm.To)
	}
	extraStr := ""
	if mm.ToOldCommittee {
		extraStr = " (To Old Committee)"
	}
	return fmt.Sprintf("Type: %s, From: %s, To: %s%s", mm.MsgType, mm.From.String(), toStr, extraStr)
}
