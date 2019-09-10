package tss

import (
	"fmt"

	"github.com/golang/protobuf/proto"
)

type (
	Message interface {
		GetTo() []*PartyID
		GetFrom() *PartyID
		Type() string
		Content() MessageContent
		IsBroadcast() bool
		IsToOldCommittee() bool
		ValidateBasic() bool
		String() string
	}

	MessageMetadata struct {
		// if `To` is `nil` the message should be broadcast to all parties
		To             []*PartyID
		From           *PartyID
		MsgType        string
		ToOldCommittee bool // only `true` in DGRound2NewCommitteeACKMessage (regroup)
	}

	// MessageContent implements ValidateBasic
	MessageContent interface {
		proto.Message
		ValidateBasic() bool
	}

	MessageImpl struct {
		MessageMetadata
		Msg MessageContent
	}
)

var _ Message = (*MessageImpl)(nil)

func (mm *MessageImpl) GetTo() []*PartyID {
	return mm.To
}

func (mm *MessageImpl) GetFrom() *PartyID {
	return mm.From
}

func (mm *MessageImpl) Type() string {
	return mm.MsgType
}

func (mm *MessageImpl) Content() MessageContent {
	return mm.Msg
}

func (mm *MessageImpl) IsBroadcast() bool {
	return mm.To == nil || len(mm.To) > 1
}

func (mm *MessageImpl) IsToOldCommittee() bool {
	return mm.ToOldCommittee
}

func (mm *MessageImpl) ValidateBasic() bool {
	return mm.Msg.ValidateBasic()
}

func (mm *MessageImpl) String() string {
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
