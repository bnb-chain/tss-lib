package regroup

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
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants = 20
	testThreshold    = testParticipants / 2
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
	keys := make([]keygen.LocalPartySaveData, len(pIDs), len(pIDs))

	// PHASE: load keygen fixtures
	keys, err := keygen.LoadKeygenTestFixtures(len(pIDs))
	assert.NoError(t, err, "should load keygen fixtures")

	// PHASE: regroup
	pIDs = pIDs[:threshold+1] // always regroup with old_t+1
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

	// init the old parties first
	for i, pID := range pIDs {
		params := tss.NewReGroupParameters(p2pCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold)
		P := NewLocalParty(params, keys[i], outCh, nil) // discard old key data
		oldCommittee = append(oldCommittee, P)
	}
	// init the new parties
	for _, pID := range newPIDs {
		params := tss.NewReGroupParameters(p2pCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold)
		// TODO do this better!
		save := keygen.LocalPartySaveData{
			BigXj:       make([]*crypto.ECPoint, newPCount),
			PaillierPks: make([]*paillier.PublicKey, newPCount),
			NTildej:     make([]*big.Int, newPCount),
			H1j:         make([]*big.Int, newPCount),
			H2j:         make([]*big.Int, newPCount),
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

	var regroupEnded int32
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
				t.Fatal("did not expect a msg to have a nil destination during regroup")
			}
			for _, destP := range dest {
				go func(P *LocalParty) {
					if _, err := P.Update(msg, "regroup"); err != nil {
						errCh <- err
					}
				}(destParties[destP.Index])
			}

		case save := <-endCh:
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			keys[index] = save
			atomic.AddInt32(&regroupEnded, 1)
			if atomic.LoadInt32(&regroupEnded) == int32(len(newCommittee)) {
				t.Logf("Regroup done. Regrouped %d participants", regroupEnded)

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
	keys = keys[:threshold+1]
	signPIDs := newPIDs[:threshold+1]

	signP2pCtx := tss.NewPeerContext(signPIDs)
	signParties := make([]*signing.LocalParty, 0, len(signPIDs))

	signErrCh := make(chan *tss.Error, len(signPIDs))
	signOutCh := make(chan tss.Message, len(signPIDs))
	signEndCh := make(chan signing.LocalPartySignData, len(signPIDs))

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
					go func(P *signing.LocalParty, msg tss.Message) {
						if _, err := P.Update(msg, "sign"); err != nil {
							signErrCh <- err
						}
					}(P, msg)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go func(P *signing.LocalParty) {
					if _, err := P.Update(msg, "sign"); err != nil {
						signErrCh <- err
					}
				}(signParties[dest[0].Index])
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
