package tss

import (
	"fmt"

	"github.com/golang/protobuf/proto"

	"github.com/binance-chain/tss-lib/tss/wire"
)

type (
	WireMessage interface {
		GetTo() []*PartyID
		GetFrom() *PartyID
		Type() string
		IsBroadcast() bool
		IsToOldCommittee() bool
		WireMsg() *wire.Message
		WireBytes() ([]byte, error)
		String() string
	}

	Message interface {
		WireMessage
		Content() MessageContent
		ValidateBasic() bool
	}

	// MessageContent implements ValidateBasic
	MessageContent interface {
		proto.Message
		ValidateBasic() bool
	}

	MessageMetadata struct {
		// if `To` is `nil` the message should be broadcast to all parties
		To             []*PartyID
		From           *PartyID
		ToOldCommittee bool // only `true` in DGRound2NewCommitteeACKMessage (regroup)
	}

	MessageImpl struct {
		MessageMetadata
		Msg  MessageContent
		Wire *wire.Message
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
	return proto.MessageName(mm.Msg)
}

func (mm *MessageImpl) Content() MessageContent {
	return mm.Msg
}

func (mm *MessageImpl) WireMsg() *wire.Message {
	return mm.Wire
}

func (mm *MessageImpl) WireBytes() ([]byte, error) {
	return proto.Marshal(mm.WireMsg())
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
	return fmt.Sprintf("Type: %s, From: %s, To: %s%s", mm.Type(), mm.From.String(), toStr, extraStr)
}
