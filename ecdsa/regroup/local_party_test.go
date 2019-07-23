package regroup

import (
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

	threshold := testThreshold
	newThreshold := testThreshold

	pIDs := tss.GenerateTestPartyIDs(testParticipants)
	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*keygen.LocalParty, 0, len(pIDs))

	out := make(chan tss.Message, len(pIDs))
	end := make(chan keygen.LocalPartySaveData, len(pIDs))
	keys := make([]keygen.LocalPartySaveData, len(pIDs), len(pIDs))

	// init `parties`
	for i := 0; i < len(pIDs); i++ {
		params := tss.NewParameters(p2pCtx, pIDs[i], len(pIDs), threshold)
		P := keygen.NewLocalParty(params, out, end)
		parties = append(parties, P)
		go func(P *keygen.LocalParty) {
			if err := P.Start(); err != nil {
				common.Logger.Errorf("Error: %s", err)
				assert.FailNow(t, err.Error())
			}
		}(P)
	}

	common.Logger.Info("[regroup.TestE2EConcurrent] Starting keygen")

	// PHASE: keygen
	var ended int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case msg := <-out:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index != msg.GetFrom().Index {
						go func(P *keygen.LocalParty, msg tss.Message) {
							if _, err := P.Update(msg, "keygen"); err != nil {
								common.Logger.Errorf("Error: %s", err)
								assert.FailNow(t, err.Error()) // TODO fail outside goroutine
							}
						}(P, msg)
					}
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go func(P *keygen.LocalParty) {
					if _, err := P.Update(msg, "keygen"); err != nil {
						common.Logger.Errorf("Error: %s", err)
						assert.FailNow(t, err.Error()) // TODO fail outside goroutine
					}
				}(parties[dest[0].Index])
			}
		case save := <-end:
			atomic.AddInt32(&ended, 1)
			keys[save.Index] = save
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Keygen done. Received save data from %d participants", ended)

				// more verification of signing is implemented within local_party_test.go of keygen package
				goto regroup
			}
		}
	}

regroup:
	// PHASE: regroup
	common.Logger.Info("[regroup.TestE2EConcurrent] Starting regroup")

	newPIDs := tss.GenerateTestPartyIDs(testParticipants) // new group (start from new index)
	newP2PCtx := tss.NewPeerContext(newPIDs)

	oldCommittee := make([]*LocalParty, 0, len(pIDs))
	newCommittee := make([]*LocalParty, 0, len(newPIDs))

	regroupOut := make(chan tss.Message, len(oldCommittee) + len(newCommittee))
	regroupEnd := make(chan keygen.LocalPartySaveData, len(oldCommittee) + len(newCommittee))

	// init `newParties`; add the old parties first
	for i, pID := range pIDs {
		params := tss.NewReGroupParameters(p2pCtx, newP2PCtx, pID, testParticipants, threshold, len(newPIDs), newThreshold)
		save := keys[i]
		P := NewLocalParty(params, save, regroupOut, regroupEnd)
		oldCommittee = append(oldCommittee, P)
	}
	// add the new parties
	for _, pID := range newPIDs {
		params := tss.NewReGroupParameters(p2pCtx, newP2PCtx, pID, testParticipants, threshold, len(newPIDs), newThreshold)
		// TODO do this better!
		save := keygen.LocalPartySaveData{
			BigXj: make([]*crypto.ECPoint, len(newPIDs)),
			PaillierPks: make([]*paillier.PublicKey, len(newPIDs)),
			NTildej: make([]*big.Int, len(newPIDs)),
			H1j: make([]*big.Int, len(newPIDs)),
			H2j: make([]*big.Int, len(newPIDs)),
		}
		P := NewLocalParty(params, save, regroupOut, regroupEnd)
		newCommittee = append(newCommittee, P)
	}

	// start the new parties; they will wait for messages
	for _, P := range newCommittee {
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				common.Logger.Errorf("Error: %s", err)
				assert.FailNow(t, err.Error())
			}
		}(P)
	}
	// start the old parties; they will send messages
	for _, P := range oldCommittee {
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				common.Logger.Errorf("Error: %s", err)
				assert.FailNow(t, err.Error())
			}
		}(P)
	}

	var regroupEnded int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case msg := <-regroupOut:
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
						common.Logger.Errorf("Error: %s", err)
						assert.FailNow(t, err.Error()) // TODO fail outside goroutine
					}
				}(destParties[destP.Index])
			}
		case save := <-regroupEnd:
			atomic.AddInt32(&regroupEnded, 1)
			keys[save.Index] = save
			if atomic.LoadInt32(&regroupEnded) == int32(len(oldCommittee) + len(newCommittee)) {
				t.Logf("Done. Received save data from %d participants", regroupEnded)

				// more verification of signing is implemented within local_party_test.go of keygen package
				goto signing
			}
		}
	}

signing:
	// PHASE: signing
	common.Logger.Info("[regroup.TestE2EConcurrent] Starting signing")

	signPIDs := pIDs[:testThreshold+1]

	signP2pCtx := tss.NewPeerContext(signPIDs)
	signParties := make([]*signing.LocalParty, 0, len(signPIDs))

	signOut := make(chan tss.Message, len(signPIDs))
	signEnd := make(chan signing.LocalPartySignData, len(signPIDs))

	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(signP2pCtx, signPIDs[i], len(signPIDs), threshold)
		P := signing.NewLocalParty(big.NewInt(42), params, keys[i], signOut, signEnd)
		signParties = append(signParties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				common.Logger.Errorf("Error: %s", err)
				assert.FailNow(t, err.Error())
			}
		}(P)
	}

	var signEnded int32
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case msg := <-signOut:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range signParties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go func(P *signing.LocalParty, msg tss.Message) {
						if _, err := P.Update(msg, "sign"); err != nil {
							common.Logger.Errorf("Error: %s", err)
							assert.FailNow(t, err.Error()) // TODO fail outside goroutine
						}
					}(P, msg)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go func(P *signing.LocalParty) {
					if _, err := P.Update(msg, "sign"); err != nil {
						common.Logger.Errorf("Error: %s", err)
						assert.FailNow(t, err.Error()) // TODO fail outside goroutine
					}
				}(signParties[dest[0].Index])
			}
		case <-signEnd:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				return
			}
		}
	}
}
