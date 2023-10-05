// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mpc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

type FSLMPCPublicKey struct {
	Curve  string `json:"Curve"`
	X      string `json:"X"`
	Y      string `json:"Y"`
	Encode string `json:"Encode"`
}

type FSLMPCSignInfo struct {
	PublicKey *FSLMPCPublicKey `json:"PublicKey"`
	Message   string           `json:"Message"`
	R         string           `json:"R"`
	S         string           `json:"S"`
	Rec       string           `json:"Rec"`
	Encode    string           `json:"Encode"`
}

func Reverse(s []byte) []byte {
	ret := make([]byte, len(s))
	for i := 0; i < len(s)/2; i++ {
		ret[len(s)-(i+1)] = s[i]
		ret[i] = s[len(s)-(i+1)]
	}
	return ret
}

func MakeMoniker(groupId string, totalCount int, threshold int) string {
	return fmt.Sprintf("%s[%d-of-%d]", groupId, threshold, totalCount)
}

func MakeParty(groupId string, totalCount int, threshold int, index int, shareID *big.Int) *tss.PartyID {
	// return tss.NewPartyID(fmt.Sprintf("%d", index+1), fmt.Sprintf("%d", total), shareID)
	moniker := MakeMoniker(groupId, totalCount, threshold)
	pId := fmt.Sprintf("%s[%d]", moniker, index+1)
	return tss.NewPartyID(pId, moniker, shareID)
}

func MakeInitParties(groupId string, totalCount int, threshold int) tss.SortedPartyIDs {
	var unSortedParties tss.UnSortedPartyIDs
	for index := 0; index < totalCount; index++ {
		keyBytes, err := hex.DecodeString(MakeHashFromString(fmt.Sprintf("FSL[%s]FSL[%d-of-%d]FSL[%d]", groupId, threshold, totalCount, index)))
		if nil != err {
			panic(err)
		}
		unSortedParties = append(unSortedParties, MakeParty(groupId, totalCount, threshold, index, new(big.Int).SetBytes(keyBytes)))
	}
	return tss.SortPartyIDs(unSortedParties)
}

func LoadParties(groupId string, totalCount int, threshold int, indexes []int, savedKSs []*big.Int) tss.SortedPartyIDs {
	var unSortedParties tss.UnSortedPartyIDs
	for _, index := range indexes {
		unSortedParties = append(unSortedParties, MakeParty(groupId, totalCount, threshold, index, savedKSs[index]))
	}
	return tss.SortPartyIDs(unSortedParties)
}

func getCommonPath(algo string, groupId string, totalCount int, threshold int, index int) string {
	return fmt.Sprintf("%s_%s[%d-of-%d][%d]", algo, groupId, threshold, totalCount, index)
}

func getKeyPath(algo string, groupId string, totalCount int, threshold int, index int) string {
	common := getCommonPath(algo, groupId, totalCount, threshold, index)
	return fmt.Sprintf("./keys/%s", common)
}

func GetKeyFilePath(algo string, groupId string, totalCount int, threshold int, index int) string {
	path := getKeyPath(algo, groupId, totalCount, threshold, index)
	if err := os.MkdirAll(path, os.ModePerm); nil != err {
		panic(err)
	}
	return fmt.Sprintf("%s/key.json", path)
}

func getSharePath(step string, algo string, groupId string, totalCount int, threshold int, index int) string {
	common := getCommonPath(algo, groupId, totalCount, threshold, index)
	return fmt.Sprintf("./../sharedatas/%s/%s", step, common)
}

func ResetShareData(step string, algo string, groupId string, totalCount int, threshold int, index int) {
	sharePath := getSharePath(step, algo, groupId, totalCount, threshold, index)
	os.RemoveAll(sharePath)
}

func GetShareFilePath(step string, algo string, groupId string, totalCount int, threshold int, isBroadcast bool, msgType string, from int, to int) string {
	path := getSharePath(step, algo, groupId, totalCount, threshold, from)

	shareType := "p2p"
	if true == isBroadcast {
		shareType = "all"
	}
	path += "/" + shareType

	msgTypes := strings.Split(msgType, ".")
	path += "_" + msgTypes[len(msgTypes)-1]

	if err := os.MkdirAll(path, os.ModePerm); nil != err {
		panic(err)
	}
	return fmt.Sprintf("%s/%d.json", path, to)
}

type ShareData struct {
	From        *tss.PartyID `json:"From"`
	To          *tss.PartyID `json:"To"`
	IsBroadcast bool         `json:"IsBroadcast"`
	HexData     string       `json:"HexData"`
}

func SharedPartyUpdater(step string, algo string, groupId string, totalCount int, threshold int,
	fromParty tss.Party, toParty tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	if toParty.PartyID() == fromParty.PartyID() {
		return
	}
	bz, _, err := msg.WireBytes()
	if err != nil {
		panic(err)
	}

	sendShareData := ShareData{
		From:        fromParty.PartyID(),
		To:          toParty.PartyID(),
		IsBroadcast: msg.IsBroadcast(),
		HexData:     hex.EncodeToString(bz),
	}
	bSendShareData, err := json.MarshalIndent(sendShareData, "", "  ")
	if nil != err {
		panic(err)
	}

	writeFilePath := GetShareFilePath(step, algo, groupId, totalCount, threshold, msg.IsBroadcast(), msg.Type(),
		fromParty.PartyID().Index, toParty.PartyID().Index)
	wFD, err := os.OpenFile(writeFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}

	_, err = wFD.Write(bSendShareData)
	if err != nil {
		panic(err)
	}

	waitCount := 0
	readFilePath := GetShareFilePath(step, algo, groupId, totalCount, threshold, msg.IsBroadcast(), msg.Type(),
		toParty.PartyID().Index, fromParty.PartyID().Index)
	for {
		rFD, err := os.Open(readFilePath)
		if nil != err {
			if false == os.IsNotExist(err) {
				panic(err.Error())
			}

			waitCount++
			if 120 < waitCount {
				panic(fmt.Sprintf("party[%d] wait over 2 Min party[%d]'s message[%s]\n", fromParty.PartyID().Index,
					toParty.PartyID().Index, msg.Type()))
			}
			time.Sleep(1 * time.Second)
			continue
		}

		bRecvShareData, err := ioutil.ReadAll(rFD)
		if err != nil {
			panic(err.Error())
		}

		recvShareData := ShareData{}
		err = json.Unmarshal(bRecvShareData, &recvShareData)
		if err != nil {
			panic(err.Error())
		}

		bz, err = hex.DecodeString(recvShareData.HexData)
		if err != nil {
			panic(err.Error())
		}

		pMsg, err := tss.ParseWireMessage(bz, toParty.PartyID(), recvShareData.IsBroadcast)
		if err != nil {
			errCh <- toParty.WrapError(err)
			return
		}

		if _, err2 := fromParty.Update(pMsg); err2 != nil {
			errCh <- err2
		}
		// os.Remove(readFilePath)
		break
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
