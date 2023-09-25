// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package eddsa

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"sync/atomic"

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

func SigningProc(threshold int, totalCount int, signIndexes []int, message []byte) *mpc.MPCSignRet {
	ret := &mpc.MPCSignRet{}
	if totalCount < threshold || threshold != len(signIndexes) {
		panic(fmt.Sprintf("n[%d]-of-m[%d] and singerCount[%d] invalid\n", threshold, totalCount, len(signIndexes)))
	}

	sort.Ints(signIndexes)
	keys, signPIDs, lErr := LoadKeys(signIndexes, totalCount)
	if nil != lErr {
		panic(lErr)
	}

	signerCount := len(signPIDs)
	if totalCount < threshold || threshold != signerCount {
		panic(fmt.Sprintf("n[%d]-of-m[%d] and singerCount[%d] invalid\n", threshold, totalCount, signerCount))
	}

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*signing.LocalParty, 0, signerCount)

	errCh := make(chan *tss.Error, signerCount)
	outCh := make(chan tss.Message, signerCount)
	endCh := make(chan *common.SignatureData, signerCount)

	updater := mpc.SharedPartyUpdater

	for i, signPID := range signPIDs {
		var P *signing.LocalParty
		params := tss.NewParameters(tss.Edwards(), p2pCtx, signPID, signerCount, threshold-1)
		P = signing.NewLocalParty(new(big.Int).SetBytes(message), params, *keys[i], outCh, endCh).(*signing.LocalParty)
		parties = append(parties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		select {
		case err := <-errCh:
			panic(fmt.Sprintf("signing Error: %s\n", err))

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				fmt.Printf("msg[%s] broadcast [%d] => all\n", msg.Type(), msg.GetFrom().Index)
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				fmt.Printf("msg[%s] p2p [%d] => [%d]\n", msg.Type(), msg.GetFrom().Index, dest[0].Index)
				if dest[0].Index == msg.GetFrom().Index {
					panic(fmt.Sprintf("party %d tried to send a message to itself (%d)\n", dest[0].Index, msg.GetFrom().Index))
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case sign := <-endCh:
			r, s := new(big.Int).SetBytes(sign.GetR()), new(big.Int).SetBytes(sign.GetS())
			pub, mPub := getPubEncode(keys[0])
			if true != edwards.Verify(pub, sign.GetM(), r, s) {
				panic(fmt.Sprintf("sig(r:[%s], s:[%s]) verify failed", r.Text(16), s.Text(16)))
			}

			ret.PublicKey = mPub
			ret.R = r.Text(16)
			ret.S = s.Text(16)
			ret.Hash = hex.EncodeToString(sign.GetM())
			ret.Encode = getSigEncode(r, s)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				break signing
			}
		}
	}

	return ret
}
