// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/agl/ed25519/edwards25519"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/eddsa/keygen"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func TestE2EConcurrent(t *testing.T) {
	setUp("info")

	tss.SetCurve(edwards.Edwards())

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200)
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(msg, params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
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
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)
				R := parties[0].temp.r

				// BEGIN check s correctness
				sumS := parties[0].temp.si
				for i, p := range parties {
					if i == 0 {
						continue
					}

					var tmpSumS [32]byte
					edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), p.temp.si)
					sumS = &tmpSumS
				}
				fmt.Printf("S: %s\n", encodedBytesToBigInt(sumS).String())
				fmt.Printf("R: %s\n", R.String())
				// END check s correctness

				// BEGIN EDDSA verify
				pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()
				pk := edwards.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}

				newSig, err := edwards.ParseSignature(parties[0].data.Signature)
				if err != nil {
					println("new sig error, ", err.Error())
				}

				ok := edwards.Verify(&pk, msg.Bytes(), newSig.R, newSig.S)
				assert.True(t, ok, "eddsa verify must pass")
				t.Log("EDDSA signing test done.")
				// END EDDSA verify

				break signing
			}
		}
	}
}
