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

	"github.com/binance-chain/tss-lib/protob"
)

const (
	ProtoNamePrefix = "binance.tss-lib.ecdsa."
)

func ParseMessageFromProtoB(wire *protob.Message, from *PartyID) (ParsedMessage, error) {
	var any ptypes.DynamicAny
	meta := MessageMetadata{
		From: from,
	}
	if err := ptypes.UnmarshalAny(wire.Message, &any); err != nil {
		return nil, err
	}
	if content, ok := any.Message.(MessageContent); ok {
		return NewMessage(meta, content, wire), nil
	}
	return nil, errors.New("ParseMessage: the message contained unknown content")
}

// Used externally to update a LocalParty with a valid ParsedMessage
func ParseMessage(wireBytes []byte, from *PartyID) (ParsedMessage, error) {
	wire := new(protob.Message)
	if err := proto.Unmarshal(wireBytes, wire); err != nil {
		return nil, err
	}
	return ParseMessageFromProtoB(wire, from)
}
