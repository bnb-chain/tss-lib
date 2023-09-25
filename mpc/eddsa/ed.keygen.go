// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package eddsa

import (
	"encoding/hex"
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"

	"github.com/bnb-chain/tss-lib/v2/mpc"
)

func getPubEncode(keyInfo *keygen.LocalPartySaveData) (*edwards.PublicKey, *mpc.MPCPublicKey) {
	pub := &edwards.PublicKey{
		Curve: tss.EC(),
		X:     keyInfo.EDDSAPub.X(),
		Y:     keyInfo.EDDSAPub.Y(),
	}

	var hexPubX = pub.X.Text(16)
	for 64 > len(hexPubX) {
		hexPubX = "0" + hexPubX
	}
	var hexPubY = pub.Y.Text(16)
	for 64 > len(hexPubY) {
		hexPubY = "0" + hexPubY
	}

	return pub, &mpc.MPCPublicKey{
		Curve: pub.Curve.Params().Name,
		Coords: mpc.MPCPoint{
			X: hexPubX,
			Y: hexPubY,
		},
		Encode: hex.EncodeToString(pub.Serialize()),
	}
}

func KeygenProc(threshold int, totalCount int) ([]int, *mpc.MPCPublicKey) {
	var savedIndexes []int
	var masterPublicKey *mpc.MPCPublicKey
	if totalCount < threshold {
		panic(fmt.Sprintf("n[%d]-of-m[%d] invalid\n", threshold, totalCount))
	}

	pIDs := mpc.MakeInitParties(totalCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	errCh := make(chan *tss.Error, totalCount)
	outCh := make(chan tss.Message, totalCount)
	endCh := make(chan *keygen.LocalPartySaveData, totalCount)
	parties := make([]*keygen.LocalParty, 0, totalCount)

	updater := mpc.SharedPartyUpdater

	for _, curPartyId := range pIDs {
		var P *keygen.LocalParty
		params := tss.NewParameters(tss.Edwards(), p2pCtx, curPartyId, totalCount, threshold-1)
		P = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
		parties = append(parties, P)

		go func(P *keygen.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
keygen:
	for {
		select {
		case err := <-errCh:
			panic(fmt.Sprintf("keygen Error: %s\n", err))

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				fmt.Printf("msg[%s] broadcast [%d] => all\n", msg.Type(), msg.GetFrom().Index)
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				fmt.Printf("msg[%s] p2p [%d] => [%d]\n", msg.Type(), msg.GetFrom().Index, dest[0].Index)
				if dest[0].Index == msg.GetFrom().Index {
					panic(fmt.Sprintf("party %d tried to send a message to itself (%d)\n", dest[0].Index, msg.GetFrom().Index))
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			index, err := save.OriginalIndex()
			if nil != err {
				panic(fmt.Sprintf("should not be an error getting a party's index from save data [%s]", err))
			}

			if len(savedIndexes) >= totalCount {
				panic(fmt.Sprintf("already saved indexes[%v] current[%d] over total count[%d]\n", savedIndexes, index, totalCount))
			}

			SaveKey(index, save)
			_, masterPublicKey = getPubEncode(save)
			savedIndexes = append(savedIndexes, index)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				sort.Ints(savedIndexes)
				break keygen
			}
		}
	}

	return savedIndexes, masterPublicKey
}
