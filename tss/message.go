// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type (
	// Message describes the interface of the TSS Message for all protocols
	Message interface {
		// Type is encoded in the protobuf Any structure
		Type() string
		// The set of parties that this message should be sent to
		GetTo() []*PartyID
		// The party that this message is from
		GetFrom() *PartyID
		// Indicates whether the message should be broadcast to other participants
		IsBroadcast() bool
		// Indicates whether the message is to the old committee during re-sharing; used mainly in tests
		IsToOldCommittee() bool
		// Indicates whether the message is to both committees during re-sharing; used mainly in tests
		IsToOldAndNewCommittees() bool
		// Returns the encoded inner message bytes to send over the wire along with metadata about how the message should be delivered
		WireBytes() ([]byte, *MessageRouting, error)
		// Returns the protobuf message wrapper struct
		// Only its inner content should be sent over the wire, not this struct itself
		WireMsg() *MessageWrapper
		String() string
	}

	// ParsedMessage represents a message with inner ProtoBuf message content
	ParsedMessage interface {
		Message
		Content() MessageContent
		ValidateBasic() bool
	}

	// MessageContent represents a ProtoBuf message with validation logic
	MessageContent interface {
		proto.Message
		ValidateBasic() bool
	}

	// MessageRouting holds the full routing information for the message, consumed by the transport
	MessageRouting struct {
		// which participant this message came from
		From *PartyID
		// when `nil` the message should be broadcast to all parties
		To []*PartyID
		// whether the message should be broadcast to other participants
		IsBroadcast bool
		// whether the message should be sent to old committee participants rather than the new committee
		IsToOldCommittee bool
		// whether the message should be sent to both old and new committee participants
		IsToOldAndNewCommittees bool
	}

	// Implements ParsedMessage; this is a concrete implementation of what messages produced by a LocalParty look like
	MessageImpl struct {
		MessageRouting
		content MessageContent
		wire    *MessageWrapper
	}
)

var (
	_ Message       = (*MessageImpl)(nil)
	_ ParsedMessage = (*MessageImpl)(nil)
)

// ----- //

// NewMessageWrapper constructs a MessageWrapper from routing metadata and content
func NewMessageWrapper(routing MessageRouting, content MessageContent) *MessageWrapper {
	// marshal the content to the ProtoBuf Any type
	any, _ := anypb.New(content)
	// convert given PartyIDs to the wire format
	var to []*MessageWrapper_PartyID
	if routing.To != nil {
		to = make([]*MessageWrapper_PartyID, len(routing.To))
		for i := range routing.To {
			to[i] = routing.To[i].MessageWrapper_PartyID
		}
	}
	return &MessageWrapper{
		IsBroadcast:             routing.IsBroadcast,
		IsToOldCommittee:        routing.IsToOldCommittee,
		IsToOldAndNewCommittees: routing.IsToOldAndNewCommittees,
		From:                    routing.From.MessageWrapper_PartyID,
		To:                      to,
		Message:                 any,
	}
}

// ----- //

func NewMessage(meta MessageRouting, content MessageContent, wire *MessageWrapper) ParsedMessage {
	return &MessageImpl{
		MessageRouting: meta,
		content:        content,
		wire:           wire,
	}
}

func (mm *MessageImpl) Type() string {
	return string(proto.MessageName(mm.content))
}

func (mm *MessageImpl) GetTo() []*PartyID {
	return mm.To
}

func (mm *MessageImpl) GetFrom() *PartyID {
	return mm.From
}

func (mm *MessageImpl) IsBroadcast() bool {
	return mm.wire.IsBroadcast
}

// only `true` in DGRound2Message (resharing)
func (mm *MessageImpl) IsToOldCommittee() bool {
	return mm.wire.IsToOldCommittee
}

// only `true` in DGRound4Message (resharing)
func (mm *MessageImpl) IsToOldAndNewCommittees() bool {
	return mm.wire.IsToOldAndNewCommittees
}

func (mm *MessageImpl) WireBytes() ([]byte, *MessageRouting, error) {
	bz, err := proto.Marshal(mm.wire.Message)
	if err != nil {
		return nil, nil, err
	}
	return bz, &mm.MessageRouting, nil
}

func (mm *MessageImpl) WireMsg() *MessageWrapper {
	return mm.wire
}

func (mm *MessageImpl) Content() MessageContent {
	return mm.content
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
