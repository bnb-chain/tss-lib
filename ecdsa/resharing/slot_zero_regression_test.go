// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	resharing "github.com/bnb-chain/tss-lib/v4/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v4/test"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// TestResharingRejectsSlotZeroPubKeySwap is a regression test for SRC-2026-1155
// ("Resharing Slot-0 Public-Key Swap"). The new committee's round-1 continuity
// check must reject an old-committee party that advertises an aggregate public
// key differing from the other old parties.
//
// Before the fix, round-1 Update() read round.temp.dgRound1Messages[0] on every
// iteration instead of the loop's current message, so the intended
// "every old party must advertise the same key" comparison degenerated to
// "slot 0 == slot 0" and never fired. A malicious old slot-0 party could
// therefore swap the reshared public key undetected. This test drives real
// new-committee parties and injects two conflicting old round-1 broadcasts; the
// mismatch must now surface as a round-1 error. Against the buggy code this test
// times out (no error is ever raised).
func TestResharingRejectsSlotZeroPubKeySwap(t *testing.T) {
	setUp("info")
	ec := tss.S256()

	threshold, newThreshold := testThreshold, testThreshold
	oldPIDs := tss.GenerateTestPartyIDs(testThreshold + 1) // old committee
	newPIDs := tss.GenerateTestPartyIDs(testParticipants)  // new committee
	oldCtx := tss.NewPeerContext(oldPIDs)
	newCtx := tss.NewPeerContext(newPIDs)
	newPCount := len(newPIDs)

	// pre-params are only needed by later rounds; round 1 never reaches them.
	fixtures, _, err := keygen.LoadKeygenTestFixtures(testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")

	errCh := make(chan *tss.Error, newPCount)
	outCh := make(chan tss.Message, newPCount*8)
	endCh := make(chan *keygen.LocalPartySaveData, newPCount)

	newCommittee := make([]*resharing.LocalParty, 0, newPCount)
	for j, pID := range newPIDs {
		params := tss.NewReSharingParameters(ec, oldCtx, newCtx, pID, len(oldPIDs), threshold, newPCount, newThreshold)
		params.SetSessionNonce(big.NewInt(1))
		save := keygen.NewLocalPartySaveData(newPCount)
		if j < len(fixtures) {
			save.LocalPreParams = fixtures[j].LocalPreParams
		}
		P := resharing.NewLocalParty(params, save, outCh, endCh).(*resharing.LocalParty)
		newCommittee = append(newCommittee, P)
	}
	for _, P := range newCommittee {
		go func(P *resharing.LocalParty) {
			if startErr := P.Start(); startErr != nil {
				errCh <- startErr
			}
		}(P)
	}

	// Old slot 0 advertises the "honest" aggregate key; old slot 1 advertises a
	// forged (different) one. The two keys are valid curve points; the round-1
	// check compares them before any commitment/VSS is opened, so dummy
	// commitment/ssid values are sufficient to exercise the continuity check.
	honestPub := crypto.ScalarBaseMult(ec, big.NewInt(11))
	forgedPub := crypto.ScalarBaseMult(ec, big.NewInt(22))
	ssid := []byte("slot-zero-regression-ssid")
	msg0 := resharing.NewDGRound1Message(newPIDs, oldPIDs[0], honestPub, big.NewInt(1), ssid, []byte("nonce-hash"))
	msg1 := resharing.NewDGRound1Message(newPIDs, oldPIDs[1], forgedPub, big.NewInt(1), ssid, []byte("nonce-hash"))

	for _, P := range newCommittee {
		go test.SharedPartyUpdater(P, msg0, errCh)
		go test.SharedPartyUpdater(P, msg1, errCh)
	}

	select {
	case err := <-errCh:
		assert.Contains(t, err.Error(), "ecdsa pub key did not match",
			"round 1 must reject an old party advertising a mismatching public key")
	case <-time.After(20 * time.Second):
		t.Fatal("expected a round-1 public-key mismatch error, but the swap was accepted (SRC-2026-1155 regression)")
	}
}
