// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package eddsa

import (
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/mpc"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func KeygenProc(groupId string, totalCount int, threshold int, index int) string {
	const ALGO = "EDDSA"
	const STEP = "KEYGEN"

	var saveFilePath string
	if totalCount < threshold {
		panic(fmt.Sprintf("n[%d]-of-m[%d] invalid\n", threshold, totalCount))
	}

	pIDs := mpc.MakeInitParties(groupId, totalCount, threshold)
	mpc.ResetShareData(STEP, ALGO, groupId, totalCount, threshold, index)

	p2pCtx := tss.NewPeerContext(pIDs)

	errCh := make(chan *tss.Error, totalCount)
	outCh := make(chan tss.Message, totalCount)
	endCh := make(chan *keygen.LocalPartySaveData, totalCount)
	parties := make([]*keygen.LocalParty, 0, totalCount)

	updater := mpc.SharedPartyUpdater

	for i, curPartyId := range pIDs {
		var P *keygen.LocalParty
		params := tss.NewParameters(tss.Edwards(), p2pCtx, curPartyId, totalCount, threshold-1)
		P = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)

		parties = append(parties, P)
		go func(P *keygen.LocalParty, i int) {
			if i == index {
				if err := P.Start(); err != nil {
					errCh <- err
				}
			} else {
				if err := P.RemoteStart(); err != nil {
					errCh <- err
				}
			}
		}(P, i)
	}

keygen:
	for {
		select {
		case err := <-errCh:
			panic(fmt.Sprintf("keygen Error: %s\n", err))

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

		case save := <-endCh:
			originIndex, err := save.OriginalIndex()
			if nil != err {
				panic(fmt.Sprintf("should not be an error getting a party's index from save data [%s]", err))
			}

			if index != originIndex {
				panic(fmt.Sprintf("should not be an error a party's index[%d] is not equal group index[%d]\n", index, originIndex))
			}

			saveFilePath = SaveKey(ALGO, groupId, totalCount, threshold, originIndex, save)
			break keygen
		}
	}

	return saveFilePath
}
