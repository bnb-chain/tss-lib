package tss

import (
	"fmt"

	"github.com/golang/protobuf/proto"

	"github.com/binance-chain/tss-lib/protob"
)

type (
	Message interface {
		// Type is encoded in the protobuf Any structure
		Type() string
		GetTo() []*PartyID
		GetFrom() *PartyID
		IsBroadcast() bool
		IsToOldCommittee() bool
		// Returns the encoded bytes to send over the wire
		WireBytes() ([]byte, error)
		// Returns the protobuf message struct to send over the wire
		WireMsg() *protob.Message
		String() string
	}

	ParsedMessage interface {
		Message
		Content() MessageContent
		ValidateBasic() bool
	}

	MessageContent interface {
		proto.Message
		ValidateBasic() bool
	}

	MessageMetadata struct {
		From *PartyID
		// if `To` is `nil` the message should be broadcast to all parties
		To []*PartyID
	}

	// Implements ParsedMessage
	MessageImpl struct {
		MessageMetadata
		content MessageContent
		wire    *protob.Message
	}
)

var (
	_ Message       = (*MessageImpl)(nil)
	_ ParsedMessage = (*MessageImpl)(nil)
)

func NewMessage(meta MessageMetadata, content MessageContent, wire *protob.Message) ParsedMessage {
	return &MessageImpl{
		MessageMetadata: meta,
		content:         content,
		wire:            wire,
	}
}

func (mm *MessageImpl) GetTo() []*PartyID {
	return mm.To
}

func (mm *MessageImpl) GetFrom() *PartyID {
	return mm.From
}

func (mm *MessageImpl) Type() string {
	return proto.MessageName(mm.content)
}

func (mm *MessageImpl) Content() MessageContent {
	return mm.content
}

func (mm *MessageImpl) WireBytes() ([]byte, error) {
	return proto.Marshal(mm.wire)
}

func (mm *MessageImpl) WireMsg() *protob.Message {
	return mm.wire
}

func (mm *MessageImpl) IsBroadcast() bool {
	return mm.wire.IsBroadcast
}

// only `true` in DGRound2NewCommitteeACKMessage (regroup)
func (mm *MessageImpl) IsToOldCommittee() bool {
	return mm.wire.IsToOldCommittee
}

func (mm *MessageImpl) ValidateBasic() bool {
	return mm.content.ValidateBasic()
}

func (mm *MessageImpl) String() string {
	toStr := "all"
	if mm.To != nil {
		toStr = fmt.Sprintf("%v", mm.To)
	}
	extraStr := ""
	if mm.IsToOldCommittee() {
		extraStr = " (To Old Committee)"
	}
	return fmt.Sprintf("Type: %s, From: %s, To: %s%s", mm.Type(), mm.From.String(), toStr, extraStr)
}
