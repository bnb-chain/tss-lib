// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/crypto"
	cmt "github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// Regression guard for the admission binding in LocalParty.ValidateMessage
// (SRC-2026-1721, eddsa side).
//
// WHAT BROKE. ValidateMessage picked which committee's array bound to check
// from the message TYPE, then compared only From.Index against that length. It
// never checked whether the sender belongs to the committee the type implies.
// The old and new committees have INDEPENDENT index spaces, so "old slot j" and
// "new slot j" are different parties: an old-committee-only party could, using
// its own unmodified PartyID, occupy the new-committee round-4 ACK slot at its
// own old index. One message, no forged bytes, no error raised, and the victim
// then stops waiting for a new-committee member that never spoke.
//
// WHY THESE TWO TESTS AND NOT ONE. A patch that merely scans the roster for
// MEMBERSHIP and a patch that anchors identity TO THE SLOT behave identically
// on the attack input, because the attacker is on neither new-committee slot.
// TestAdmissionRejectsIndexRewrittenGenuineMember is the arm that separates
// them, and it is the one a future refactor is most likely to undo silently.
//
// THREAT MODEL -- READ BEFORE QUOTING THE SECOND TEST.
// PartyID.Index is NOT carried on the wire: MessageWrapper_PartyID carries only
// Id/Moniker/Key, and tss.ParseWireMessage copies the caller-supplied `from`. A
// remote attacker cannot set it. The second test therefore pins a
// CALLER-INTEGRATION / defence-in-depth property with a strictly stronger
// precondition than the first. It does not describe a remotely reachable
// attack, and nothing in it bears on SRC-2026-1721's severity.

const (
	abOldN = 5 // keygen.LoadKeygenTestFixtures caps at 5
	abNewN = 4 // <= oldN-1 so an out-of-range rejection stays reachable
	abOldT = 2
	abNewT = 1
)

// abVictim builds an honest OLD-committee party and walks it to round 4 with
// payload-free round-2 ACKs from every new-committee member.
func abVictim(t *testing.T) (*LocalParty, tss.SortedPartyIDs, tss.SortedPartyIDs, *tss.ReSharingParameters) {
	t.Helper()
	fixtures, _, err := keygen.LoadKeygenTestFixtures(abOldN)
	if err != nil {
		t.Fatalf("fixtures: %v", err)
	}
	oldUnsorted := make(tss.UnSortedPartyIDs, 0, abOldN)
	for i := 0; i < abOldN; i++ {
		oldUnsorted = append(oldUnsorted, tss.NewPartyID(
			fixtures[i].ShareID.String(), fixtures[i].ShareID.String(), fixtures[i].ShareID))
	}
	oldSorted := tss.SortPartyIDs(oldUnsorted)

	newUnsorted := make(tss.UnSortedPartyIDs, 0, abNewN)
	for i := 0; i < abNewN; i++ {
		k := big.NewInt(int64(900000001 + i))
		newUnsorted = append(newUnsorted, tss.NewPartyID(k.String(), k.String(), k))
	}
	newSorted := tss.SortPartyIDs(newUnsorted)

	const victimIdx = 1
	params := tss.NewReSharingParameters(tss.Edwards(),
		tss.NewPeerContext(oldSorted), tss.NewPeerContext(newSorted),
		oldSorted[victimIdx], abOldN, abOldT, abNewN, abNewT)
	params.SetSessionNonce(big.NewInt(1234567))

	outCh := make(chan tss.Message, 64)
	endCh := make(chan *keygen.LocalPartySaveData, 4)
	victim := NewLocalParty(params, fixtures[victimIdx], outCh, endCh).(*LocalParty)
	go func() {
		for range outCh {
		}
	}()
	if err := victim.Start(); err != nil {
		t.Fatalf("victim.Start: %v", err)
	}
	for j := 0; j < abNewN; j++ {
		abDeliverOK(t, victim, NewDGRound2Message(params.OldParties().IDs(), newSorted[j]), newSorted[j])
	}
	return victim, oldSorted, newSorted, params
}

func abDeliver(t *testing.T, p *LocalParty, m tss.Message, from *tss.PartyID) (bool, *tss.Error) {
	t.Helper()
	bz, _, err := m.WireBytes()
	if err != nil {
		t.Fatalf("WireBytes: %v", err)
	}
	pm, err := tss.ParseWireMessage(bz, from, m.IsBroadcast())
	if err != nil {
		t.Fatalf("ParseWireMessage: %v", err)
	}
	return p.Update(pm)
}

func abDeliverOK(t *testing.T, p *LocalParty, m tss.Message, from *tss.PartyID) {
	t.Helper()
	if _, err := abDeliver(t, p, m, from); err != nil {
		t.Fatalf("honest message rejected during setup: %v", err)
	}
}

// TestAdmissionRejectsOldCommitteeMemberInNewSlot is the attack itself: an
// old-committee-only party sends a round-4 ACK using its own unmodified
// PartyID. Its old Index is in range for the new roster, so the bound check
// alone lets it through; only the identity-to-slot check stops it.
func TestAdmissionRejectsOldCommitteeMemberInNewSlot(t *testing.T) {
	victim, oldSorted, newSorted, params := abVictim(t)

	// Pick an old party whose Index is a valid new-committee slot, and which is
	// not on the new roster at all.
	attacker := oldSorted[0]
	if attacker.Index >= abNewN {
		t.Fatalf("attacker's old index %d is not a new-committee slot; test is vacuous", attacker.Index)
	}
	for _, n := range newSorted {
		if n.KeyInt().Cmp(attacker.KeyInt()) == 0 {
			t.Fatalf("attacker is on the new roster; committees must be disjoint")
		}
	}
	slot := attacker.Index
	assert.Nil(t, victim.temp.dgRound4Messages[slot], "slot must start empty")

	ok, uerr := abDeliver(t, victim, NewDGRound4Message(params.OldAndNewParties(), attacker), attacker)

	assert.False(t, ok, "the message must not be accepted")
	if assert.NotNil(t, uerr, "rejection must be an error, not a silent drop") {
		assert.Contains(t, uerr.Cause().Error(),
			"is not on the committee that message type comes from",
			"the rejection must name the reason")
		if assert.Len(t, uerr.Culprits(), 1, "the sender must be attributed") {
			assert.Equal(t, 0, uerr.Culprits()[0].KeyInt().Cmp(attacker.KeyInt()))
		}
	}
	assert.Nil(t, victim.temp.dgRound4Messages[slot],
		"the new-committee ACK slot must stay empty")

	// The victim must still be waiting for the genuine occupant of that slot.
	stillWaiting := false
	for _, p := range victim.WaitingFor() {
		if p.KeyInt().Cmp(newSorted[slot].KeyInt()) == 0 {
			stillWaiting = true
		}
	}
	assert.True(t, stillWaiting,
		"the victim must still be waiting for the new-committee member that never spoke")
}

// TestAdmissionRejectsIndexRewrittenGenuineMember distinguishes an
// identity-to-SLOT patch from a mere roster-MEMBERSHIP patch. The sender is a
// genuine new-committee member; only the receiver-side Index is rewritten to
// another member's slot. A membership scan would accept this. See the threat
// model note at the top of this file before quoting it.
func TestAdmissionRejectsIndexRewrittenGenuineMember(t *testing.T) {
	victim, _, newSorted, params := abVictim(t)

	const sender, slot = 2, 0
	if newSorted[sender].Index == slot {
		t.Fatalf("probe is vacuous: the sender's real index is the target slot")
	}
	assert.Nil(t, victim.temp.dgRound4Messages[slot], "slot must start empty")

	// Same wire identity (Id/Moniker/Key), only the local Index rewritten.
	spoofed := &tss.PartyID{
		MessageWrapper_PartyID: newSorted[sender].MessageWrapper_PartyID,
		Index:                  slot,
	}
	ok, uerr := abDeliver(t, victim,
		NewDGRound4Message(params.OldAndNewParties(), newSorted[sender]), spoofed)

	assert.False(t, ok, "an index-rewritten genuine member must not be accepted")
	if assert.NotNil(t, uerr, "rejection must be an error, not a silent drop") {
		assert.Contains(t, uerr.Cause().Error(),
			"is not on the committee that message type comes from")
	}
	assert.Nil(t, victim.temp.dgRound4Messages[slot], "the targeted slot must stay empty")
}

// TestAdmissionAcceptsEveryHonestMessageType is the false-rejection guard. A
// patch that rejects the attack by rejecting everything would satisfy the two
// tests above; this one fails it.
//
// Every message type ValidateMessage must classify is put through it from a
// legitimate sender, over a wire round-trip. ValidateMessage is called directly
// rather than Update because the old-committee-sourced types are addressed to
// the NEW committee -- delivering them to this old victim would drive protocol
// state the test does not set up, and it is ValidateMessage that is under test.
//
// The 2/3 split IS the property: DGRound2Message and DGRound4Message are
// new-committee-sourced, the other three old-committee-sourced. Swapping the two
// switch branches drives this test red.
func TestAdmissionAcceptsEveryHonestMessageType(t *testing.T) {
	victim, oldSorted, newSorted, params := abVictim(t)

	fixtures, _, err := keygen.LoadKeygenTestFixtures(abOldN)
	if err != nil {
		t.Fatalf("fixtures: %v", err)
	}
	pub := fixtures[0].EDDSAPub

	// Well-formed enough to clear ValidateBasic; ValidateMessage reads none of it.
	vs, shares, err := vss.Create(tss.Edwards(), abNewT, big.NewInt(7), newSorted.Keys(), rand.Reader)
	if err != nil {
		t.Fatalf("vss.Create: %v", err)
	}
	flat, err := crypto.FlattenECPoints(vs)
	if err != nil {
		t.Fatalf("FlattenECPoints: %v", err)
	}
	vcmt := cmt.NewHashCommitment(rand.Reader, flat...)

	newSourced := []struct {
		name string
		from *tss.PartyID
		msg  tss.ParsedMessage
	}{
		{"DGRound2Message", newSorted[0], NewDGRound2Message(params.OldParties().IDs(), newSorted[0])},
		{"DGRound4Message", newSorted[1], NewDGRound4Message(params.OldAndNewParties(), newSorted[1])},
	}
	oldSourced := []struct {
		name string
		from *tss.PartyID
		msg  tss.ParsedMessage
	}{
		{"DGRound1Message", oldSorted[0], NewDGRound1Message(
			params.NewParties().IDs(), oldSorted[0], pub, vcmt.C, []byte{1, 2, 3}, []byte{4, 5, 6})},
		{"DGRound3Message1", oldSorted[2], NewDGRound3Message1(
			newSorted[0], oldSorted[2], shares[0])},
		{"DGRound3Message2", oldSorted[3], NewDGRound3Message2(
			params.NewParties().IDs(), oldSorted[3], vcmt.D)},
	}

	accept := func(name string, m tss.ParsedMessage, from *tss.PartyID, committee string) {
		t.Helper()
		bz, _, err := m.WireBytes()
		if err != nil {
			t.Fatalf("%s: WireBytes: %v", name, err)
		}
		pm, err := tss.ParseWireMessage(bz, from, m.IsBroadcast())
		if err != nil {
			t.Fatalf("%s: ParseWireMessage: %v", name, err)
		}
		ok, verr := victim.ValidateMessage(pm)
		assert.Nil(t, verr, "%s from its legitimate %s-committee sender must be accepted", name, committee)
		assert.True(t, ok, "%s from its legitimate %s-committee sender must be accepted", name, committee)
	}

	for _, c := range newSourced {
		accept(c.name, c.msg, c.from, "new")
	}
	for _, c := range oldSourced {
		accept(c.name, c.msg, c.from, "old")
	}

	assert.Equal(t, 2, len(newSourced), "two types are new-committee-sourced")
	assert.Equal(t, 3, len(oldSourced), "three types are old-committee-sourced")
	assert.Equal(t, 5, len(newSourced)+len(oldSourced),
		"ValidateMessage must classify exactly five message types")
}
