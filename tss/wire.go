// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"errors"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
)

const (
	ProtoNamePrefix = "binance.tss-lib.ecdsa."
)

// Used externally to update a LocalParty with a valid ParsedMessage
func ParseWireMessage(wireBytes []byte, from *PartyID, isBroadcast bool) (ParsedMessage, error) {
	wire := new(MessageWrapper)
	wire.Message = new(any.Any)
	wire.From = from.MessageWrapper_PartyID
	wire.IsBroadcast = isBroadcast
	if err := proto.Unmarshal(wireBytes, wire.Message); err != nil {
		return nil, err
	}
	return parseWrappedMessage(wire, from)
}

func parseWrappedMessage(wire *MessageWrapper, from *PartyID) (ParsedMessage, error) {
	var any ptypes.DynamicAny
	meta := MessageRouting{
		From:        from,
		IsBroadcast: wire.IsBroadcast,
	}
	if err := ptypes.UnmarshalAny(wire.Message, &any); err != nil {
		return nil, err
	}
	if content, ok := any.Message.(MessageContent); ok {
		return NewMessage(meta, content, wire), nil
	}
	return nil, errors.New("ParseWireMessage: the message contained unknown content")
}
