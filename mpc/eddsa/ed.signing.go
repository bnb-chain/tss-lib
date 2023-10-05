// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package eddsa

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/eddsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"

	"github.com/bnb-chain/tss-lib/v2/mpc"
)

func getSigEncode(r *big.Int, s *big.Int) string {
	var hexSigR = hex.EncodeToString(mpc.Reverse(r.Bytes()))
	for 64 > len(hexSigR) {
		hexSigR = "0" + hexSigR
	}
	for 0 != len(hexSigR)%2 {
		hexSigR = "0" + hexSigR
	}
	var hexSigS = hex.EncodeToString(mpc.Reverse(s.Bytes()))
	for 64 > len(hexSigS) {
		hexSigS = "0" + hexSigS
	}
	for 0 != len(hexSigS)%2 {
		hexSigS = "0" + hexSigS
	}
	return fmt.Sprintf("%s%s", hexSigR, hexSigS)
}

func SigningProc(groupId string, totalCount int, threshold int, savedIndex int, savedSignerIndexes []int, hexMessage string) *mpc.FSLMPCSignInfo {
	const ALGO = "EDDSA"
	const STEP = "SIGNING"

	signInfo := &mpc.FSLMPCSignInfo{}
	if totalCount < threshold || threshold != len(savedSignerIndexes) {
		panic(fmt.Sprintf("n[%d]-of-m[%d] and singerCount[%d] invalid\n", threshold, totalCount, len(savedSignerIndexes)))
	}

	findIndex := false
	for _, curIndex := range savedSignerIndexes {
		if savedIndex == curIndex {
			findIndex = true
			break
		}
	}
	if false == findIndex {
		panic(fmt.Sprintf("current user index[%d] is not in singers indexes[%v]\n", savedIndex, savedSignerIndexes))
	}

	savedKey, err := LoadKey(ALGO, groupId, totalCount, threshold, savedIndex)
	if nil != err {
		panic(err)
	}
	originIndex, err := savedKey.OriginalIndex()
	if nil != err {
		panic(err)
	}
	if originIndex != savedIndex {
		panic(fmt.Sprintf("current user index[%d] is not equal savedData index[%d]\n", savedIndex, originIndex))
	}

	sort.Ints(savedSignerIndexes)
	signPIDs := mpc.LoadParties(groupId, totalCount, threshold, savedSignerIndexes, savedKey.Ks)
	curSignPID := signPIDs.FindByKey(savedKey.ShareID)
	if nil == curSignPID || 0 != bytes.Compare(curSignPID.GetKey(), savedKey.ShareID.Bytes()) {
		panic(fmt.Sprintf("current user index[%d] is not in singer shareId\n", savedIndex))
	}
	signerCount := len(signPIDs)
	mpc.ResetShareData(STEP, ALGO, groupId, totalCount, threshold, curSignPID.Index)

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*signing.LocalParty, 0, signerCount)

	errCh := make(chan *tss.Error, signerCount)
	outCh := make(chan tss.Message, signerCount)
	endCh := make(chan *common.SignatureData, signerCount)

	updater := mpc.SharedPartyUpdater

	message, err := hex.DecodeString(hexMessage)
	if nil != err {
		panic(fmt.Sprintf("message[%s] is not hex string\n", hexMessage))
	}

	for _, signPID := range signPIDs {
		var P *signing.LocalParty
		params := tss.NewParameters(tss.Edwards(), p2pCtx, signPID, signerCount, threshold-1)
		P = signing.NewLocalParty(new(big.Int).SetBytes(message), params, *savedKey, outCh, endCh).(*signing.LocalParty)
		parties = append(parties, P)
		go func(P *signing.LocalParty) {
			if P.PartyID().Index == curSignPID.Index {
				if err := P.Start(); err != nil {
					errCh <- err
				}
			}
		}(P)
	}

signing:
	for {
		select {
		case err := <-errCh:
			panic(fmt.Sprintf("signing Error: %s\n", err))

		case msg := <-outCh:
			tos := msg.GetTo()
			from := msg.GetFrom()
			if tos == nil { // broadcast!
				for _, toParty := range parties {
					if toParty.PartyID().Id == from.Id {
						continue
					}
					// fmt.Printf("msg[%s] broadcast [%s][%s][%d] => [%s][%s][%d]\n", msg.Type(),
					// 	from.Moniker, from.Id, from.Index,
					// 	toParty.PartyID().Moniker, toParty.PartyID().Id, toParty.PartyID().Index)
					go updater(STEP, ALGO, groupId, totalCount, threshold, parties[from.Index], toParty, msg, errCh)
				}
			} else { // point-to-point!
				if tos[0].Id == from.Id {
					panic(fmt.Sprintf("party [%s][%s][%d] tried to send a message to itself\n", tos[0].Moniker, tos[0].Id, tos[0].Index))
				}
				// fmt.Printf("msg[%s] p2p [%s][%s][%d] => [%s][%s][%d]\n", msg.Type(),
				// 	from.Moniker, from.Id, from.Index,
				// 	tos[0].Moniker, tos[0].Id, tos[0].Index)
				go updater(STEP, ALGO, groupId, totalCount, threshold, parties[from.Index], parties[tos[0].Index], msg, errCh)
			}

		case sign := <-endCh:
			r, s := new(big.Int).SetBytes(sign.GetR()), new(big.Int).SetBytes(sign.GetS())
			savedPub := GetPublicKeyFromSaveData(savedKey)
			if true != edwards.Verify(savedPub, sign.GetM(), r, s) {
				panic(fmt.Sprintf("sig(r:[%s], s:[%s]) verify failed", r.Text(16), s.Text(16)))
			}

			signInfo.PublicKey = GetMPCPubFromSaveData(savedKey)
			signInfo.R = r.Text(16)
			signInfo.S = s.Text(16)
			signInfo.Message = hex.EncodeToString(sign.GetM())
			signInfo.Encode = getSigEncode(r, s)

			fmt.Printf("sign verify success\n")
			break signing
		}
	}

	return signInfo
}
