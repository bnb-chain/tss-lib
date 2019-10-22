// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/ecdsa/signing"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants = keygen.TestParticipants
	testThreshold    = keygen.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func TestE2EConcurrent(t *testing.T) {
	setUp("info")

	// tss.SetCurve(elliptic.P256())

	threshold, newThreshold := testThreshold, testThreshold
	pIDs := tss.GenerateTestPartyIDs(testParticipants)

	// PHASE: load keygen fixtures
	keys, err := keygen.LoadKeygenTestFixtures(testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")

	// PHASE: resharing
	pIDs = pIDs[:threshold+1] // always resharing with old_t+1
	p2pCtx := tss.NewPeerContext(pIDs)
	newPIDs := tss.GenerateTestPartyIDs(testParticipants) // new group (start from new index)
	newP2PCtx := tss.NewPeerContext(newPIDs)
	newPCount := len(newPIDs)

	oldCommittee := make([]*LocalParty, 0, len(pIDs))
	newCommittee := make([]*LocalParty, 0, newPCount)
	bothCommitteesPax := len(oldCommittee) + len(newCommittee)

	errCh := make(chan *tss.Error, bothCommitteesPax)
	outCh := make(chan tss.Message, bothCommitteesPax)
	endCh := make(chan keygen.LocalPartySaveData, len(newCommittee))

	updater := test.SharedPartyUpdater

	// init the old parties first
	for i, pID := range pIDs {
		params := tss.NewReSharingParameters(p2pCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold)
		keyI := keygen.LocalPartySaveData{
			LocalPreParams: keygen.LocalPreParams{
				PaillierSK: keys[i].PaillierSK,
				NTildei:    keys[i].NTildei,
				H1i:        keys[i].H1i,
				H2i:        keys[i].H2i,
			},
			LocalSecrets: keygen.LocalSecrets{
				Xi:      keys[i].Xi,
				ShareID: keys[i].ShareID,
			},
			BigXj:       keys[i].BigXj[:testThreshold+1],
			PaillierPKs: keys[i].PaillierPKs[:testThreshold+1],
			NTildej:     keys[i].NTildej[:testThreshold+1],
			H1j:         keys[i].H1j[:testThreshold+1],
			H2j:         keys[i].H2j[:testThreshold+1],
			Ks:          keys[i].Ks[:testThreshold+1],
			ECDSAPub:    keys[i].ECDSAPub,
		}
		P := NewLocalParty(params, keyI, outCh, nil) // discard old key data
		oldCommittee = append(oldCommittee, P)
	}
	// init the new parties; re-use the fixture pre-params for speed
	fixtures, err := keygen.LoadKeygenTestFixtures(len(newPIDs))
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
	}
	for i, pID := range newPIDs {
		params := tss.NewReSharingParameters(p2pCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold)
		save := keygen.LocalPartySaveData{
			BigXj:       make([]*crypto.ECPoint, newPCount),
			PaillierPKs: make([]*paillier.PublicKey, newPCount),
			NTildej:     make([]*big.Int, newPCount),
			H1j:         make([]*big.Int, newPCount),
			H2j:         make([]*big.Int, newPCount),
		}
		if i < len(fixtures) && len(newPIDs) <= len(fixtures) {
			save.LocalPreParams = fixtures[i].LocalPreParams
		}
		P := NewLocalParty(params, save, outCh, endCh)
		newCommittee = append(newCommittee, P)
	}

	// start the new parties; they will wait for messages
	for _, P := range newCommittee {
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}
	// start the old parties; they will send messages
	for _, P := range oldCommittee {
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var reSharingEnded int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-outCh:
			dest := msg.GetTo()
			destParties := newCommittee
			if msg.IsToOldCommittee() {
				destParties = oldCommittee
			}
			if dest == nil {
				t.Fatal("did not expect a msg to have a nil destination during resharing")
			}
			for _, destP := range dest {
				go updater(destParties[destP.Index], msg, errCh)
			}

		case save := <-endCh:
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			keys[index] = save
			atomic.AddInt32(&reSharingEnded, 1)
			if atomic.LoadInt32(&reSharingEnded) == int32(len(newCommittee)) {
				t.Logf("Resharing done. Reshared %d participants", reSharingEnded)

				// xj tests: BigXj == xj*G
				for j, key := range keys {
					// xj test: BigXj == xj*G
					xj := key.Xi
					gXj := crypto.ScalarBaseMult(tss.EC(), xj)
					BigXj := key.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")
				}

				// more verification of signing is implemented within local_party_test.go of keygen package
				goto signing
			}
		}
	}

signing:
	// PHASE: signing
	keys, err = keygen.LoadKeygenTestFixtures(testThreshold + 1)
	assert.NoError(t, err)

	signPIDs := newPIDs[:threshold+1]

	signP2pCtx := tss.NewPeerContext(signPIDs)
	signParties := make([]*signing.LocalParty, 0, len(signPIDs))

	signErrCh := make(chan *tss.Error, len(signPIDs))
	signOutCh := make(chan tss.Message, len(signPIDs))
	signEndCh := make(chan signing.LocalSignData, len(signPIDs))

	for i, signPID := range signPIDs {
		params := tss.NewParameters(signP2pCtx, signPID, len(signPIDs), newThreshold)
		P := signing.NewLocalParty(big.NewInt(42), params, keys[i], signOutCh, signEndCh)
		signParties = append(signParties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				signErrCh <- err
			}
		}(P)
	}

	var signEnded int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-signErrCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-signOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, signErrCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(signParties[dest[0].Index], msg, signErrCh)
			}

		case signData := <-signEndCh:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				t.Logf("Signing done. Received sign data from %d participants", signEnded)

				// BEGIN ECDSA verify
				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				ok := ecdsa.Verify(&pk, big.NewInt(42).Bytes(), signData.R, signData.S)

				assert.True(t, ok, "ecdsa verify must pass")
				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				return
			}
		}
	}
}
