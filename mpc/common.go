// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mpc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type MPCPoint struct {
	X string `json:"X"`
	Y string `json:"Y"`
}

type MPCPublicKey struct {
	Curve  string   `json:"Curve"`
	Coords MPCPoint `json:"Coords"`
	Encode string   `json:"Encode"`
}

type MPCSignRet struct {
	PublicKey *MPCPublicKey `json:"PublicKey"`
	Hash      string        `json:"Hash"`
	R         string        `json:"R"`
	S         string        `json:"S"`
	Rec       string        `json:"Rec"`
	Encode    string        `json:"Encode"`
}

func Reverse(s []byte) []byte {
	ret := make([]byte, len(s))
	for i := 0; i < len(s)/2; i++ {
		ret[len(s)-(i+1)] = s[i]
		ret[i] = s[len(s)-(i+1)]
	}
	return ret
}

func MakeParty(index int, total int, shareID *big.Int) *tss.PartyID {
	return tss.NewPartyID(fmt.Sprintf("%d", index+1), fmt.Sprintf("%d", total), shareID)
}

func GetKeyPath(algo string, index int) string {
	return fmt.Sprintf("./keys/%s_key_%d.json", algo, index)
}

func MakeInitParties(total int) tss.SortedPartyIDs {
	var unSortedParties tss.UnSortedPartyIDs
	for index := 0; index < total; index++ {
		unSortedParties = append(unSortedParties, MakeParty(index, total, common.MustGetRandomInt(256)))
	}
	return tss.SortPartyIDs(unSortedParties)
}

func SharedPartyUpdater(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	// do not send a message from this party back to itself
	if party.PartyID() == msg.GetFrom() {
		return
	}
	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	if _, err := party.Update(pMsg); err != nil {
		errCh <- err
	}
}

func MakeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func MakeHashFromString(data string) string {
	dataType := reflect.TypeOf(data).Name()
	if "string" != dataType {
		panic(fmt.Sprintf("data type[%s] is not string\n", dataType))
	}

	return MakeHash([]byte(data))
}

func MakeHashFromHexString(data string) string {
	dataType := reflect.TypeOf(data).Name()
	if "string" != dataType {
		panic(fmt.Sprintf("data type[%s] is not hex string\n", dataType))
	}

	origin, err := hex.DecodeString(data)
	if nil != err {
		panic(fmt.Sprintf("data[%s] is not hex string\n", data))
	}

	return MakeHash(origin)
}

func MakeHashFromBigInt(data *big.Int) string {
	return MakeHash(data.Bytes())
}
