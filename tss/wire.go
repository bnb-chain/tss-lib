// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Used externally to update a LocalParty with a valid ParsedMessage
func ParseWireMessage(wireBytes []byte, from *PartyID, isBroadcast bool) (ParsedMessage, error) {
	wire := new(MessageWrapper)
	wire.Message = new(anypb.Any)
	wire.From = from.MessageWrapper_PartyID
	wire.IsBroadcast = isBroadcast
	if err := proto.Unmarshal(wireBytes, wire.Message); err != nil {
		return nil, err
	}
	return parseWrappedMessage(wire, from)
}

func parseWrappedMessage(wire *MessageWrapper, from *PartyID) (ParsedMessage, error) {
	m, err := wire.Message.UnmarshalNew()
	if err != nil {
		return nil, err
	}
	meta := MessageRouting{
		From:        from,
		IsBroadcast: wire.IsBroadcast,
	}
	if content, ok := m.(MessageContent); ok {
		return NewMessage(meta, content, wire), nil
	}
	return nil, errors.New("ParseWireMessage: the message contained unknown content")
}
