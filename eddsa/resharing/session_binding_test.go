// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"math/big"
	"strings"
	"testing"

	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// The new committee cannot recompute the old committee's ssid: its pre-image is
// the OLD save data. sessionNonceHash is the one value it can check against
// something of its own, so it has to be a function of the nonce and nothing else.
func TestSessionNonceHashSeparatesSessions(t *testing.T) {
	h1 := sessionNonceHash(big.NewInt(1))
	h2 := sessionNonceHash(big.NewInt(2))
	if len(h1) == 0 || len(h2) == 0 {
		t.Fatal("hash must not be empty for a valid nonce")
	}
	if string(h1) == string(h2) {
		t.Fatal("two different session nonces must not produce the same hash")
	}
	if string(h1) != string(sessionNonceHash(big.NewInt(1))) {
		t.Fatal("the hash must be deterministic")
	}
	if sessionNonceHash(nil) != nil {
		t.Fatal("a nil nonce yields no hash rather than a hash of nothing")
	}
}

// ValidateBasic must REQUIRE the field. An absent hash is exactly what a
// transcript captured before this field existed carries, and it must not be
// laundered into "nothing to compare".
func TestDGRound1MessageRequiresSessionNonceHash(t *testing.T) {
	full := &DGRound1Message{
		EddsaPubX: []byte{1}, EddsaPubY: []byte{2}, VCommitment: []byte{3},
		Ssid: []byte{4}, SessionNonceHash: []byte{5},
	}
	if !full.ValidateBasic() {
		t.Fatal("a complete message must still validate")
	}
	missing := &DGRound1Message{
		EddsaPubX: []byte{1}, EddsaPubY: []byte{2}, VCommitment: []byte{3},
		Ssid: []byte{4},
	}
	if missing.ValidateBasic() {
		t.Fatal("a message with no session nonce hash must be rejected")
	}
}

// Neither field had an upper bound. Both are produced as
// common.SHA512_256i(...).Bytes(), so 32 is the exact width a conforming sender
// can reach -- a derived bound rather than a chosen one. It matters for the
// ssid because round 2 adopts it into round.temp.ssid, so a declared length is a
// length this party carries.
func TestDGRound1MessageBoundsTheSessionFields(t *testing.T) {
	atWidth := func(n int) *DGRound1Message {
		return &DGRound1Message{
			EddsaPubX: []byte{1}, EddsaPubY: []byte{2}, VCommitment: []byte{3},
			Ssid: make([]byte, n), SessionNonceHash: make([]byte, n),
		}
	}
	if !atWidth(sessionDigestMaxBytes).ValidateBasic() {
		t.Fatal("a full-width digest must still be accepted")
	}
	if atWidth(sessionDigestMaxBytes + 1).ValidateBasic() {
		t.Fatal("one byte more than a digest cannot be one")
	}
	if atWidth(1 << 20).ValidateBasic() {
		t.Fatal("a megabyte declaration must be refused at the message layer")
	}
	if len(sessionNonceHash(big.NewInt(1))) > sessionDigestMaxBytes {
		t.Fatal("the bound must be the one the producer can actually reach")
	}

	// The ssid's emptiness stays round 2's to report, so that the refusal names
	// the sender instead of being dropped here with no attribution.
	empty := &DGRound1Message{
		EddsaPubX: []byte{1}, EddsaPubY: []byte{2}, VCommitment: []byte{3},
		SessionNonceHash: []byte{5},
	}
	if !empty.ValidateBasic() {
		t.Fatal("an empty ssid is round 2's to refuse, not this layer's")
	}
}

// A party that never set a session nonce must be told so in round 1, before it
// has exchanged anything -- not in round 2, after a full round of messages, when
// it discovers it has nothing to compare the old committee's declaration
// against. The requirement is the same for both roles, so it is checked in one
// place for both; this test covers the NEW-committee side, which is the side
// that reaches round 2 in this package.
func TestNewCommitteePartyWithoutNonceFailsInRoundOne(t *testing.T) {
	oldIDs := tss.GenerateTestPartyIDs(2)
	newIDs := tss.GenerateTestPartyIDs(2, 2)
	params := tss.NewReSharingParameters(tss.Edwards(), tss.NewPeerContext(oldIDs),
		tss.NewPeerContext(newIDs), newIDs[0], 2, 1, 2, 1) // deliberately no SetSessionNonce
	out := make(chan tss.Message, 16)
	end := make(chan *keygen.LocalPartySaveData, 4)
	p := NewLocalParty(params, keygen.NewLocalPartySaveData(2), out, end).(*LocalParty)

	err := p.FirstRound().Start()
	if err == nil {
		t.Fatal("expected round 1 to refuse a party with no session nonce")
	}
	if err.Round() != 1 {
		t.Fatalf("expected the refusal in round 1, got round %d: %v", err.Round(), err)
	}
	if !strings.Contains(err.Cause().Error(), "requires a session nonce") {
		t.Fatalf("unexpected cause: %v", err.Cause())
	}
}

// ----- //

const testOldCount = 2

// newTestRound2 builds a new-committee round 2 whose round-1 inbox is exactly
// `declarations`. Driving round 2 directly is what lets a test hand this party a
// transcript it did not take part in.
func newTestRound2(nonce *big.Int, declarations []tss.ParsedMessage) *round2 {
	oldIDs := tss.GenerateTestPartyIDs(testOldCount)
	newIDs := tss.GenerateTestPartyIDs(testOldCount, testOldCount)
	params := tss.NewReSharingParameters(tss.Edwards(), tss.NewPeerContext(oldIDs),
		tss.NewPeerContext(newIDs), newIDs[0], testOldCount, 1, testOldCount, 1)
	if nonce != nil {
		params.SetSessionNonce(nonce)
	}
	temp := &localTempData{}
	temp.dgRound1Messages = declarations
	input := keygen.NewLocalPartySaveData(testOldCount)
	save := keygen.NewLocalPartySaveData(testOldCount)
	b := &base{
		params, temp, &input, &save,
		make(chan tss.Message, 16),
		make(chan *keygen.LocalPartySaveData, 4),
		make([]bool, testOldCount), make([]bool, testOldCount),
		false, 2,
	}
	return &round2{&round1{b}}
}

// oldDeclarations forges what the whole old committee broadcast in round 1: one
// ssid, one session-nonce hash, `testOldCount` senders.
func oldDeclarations(ssid []byte, nonce *big.Int) []tss.ParsedMessage {
	oldIDs := tss.GenerateTestPartyIDs(testOldCount)
	newIDs := tss.GenerateTestPartyIDs(testOldCount, testOldCount)
	pub := crypto.ScalarBaseMult(tss.Edwards(), big.NewInt(11))
	msgs := make([]tss.ParsedMessage, testOldCount)
	for j := range msgs {
		msgs[j] = NewDGRound1Message(newIDs, oldIDs[j], pub, big.NewInt(1), ssid, sessionNonceHash(nonce))
	}
	return msgs
}

// This is the regression the whole change exists for: a complete old->new
// round-1 transcript recorded in one execution used to be accepted by a
// different execution's new committee, because the only session check compared
// the old committee's declarations to EACH OTHER -- and a recorded transcript is
// unanimous with itself.
func TestRoundTwoRejectsATranscriptFromAnotherSession(t *testing.T) {
	captured := oldDeclarations([]byte("ssid-of-session-1"), big.NewInt(1))
	round := newTestRound2(big.NewInt(2), captured) // this party is in session 2

	_, err := round.oldSSIDUnanimous()
	if err == nil {
		t.Fatal("a transcript from another session must not be accepted")
	}
	if !strings.Contains(err.Cause().Error(), "not in the same session") {
		t.Fatalf("expected a session mismatch, got: %v", err.Cause())
	}
	// Single-message-visible fault => the sender is named.
	if len(err.Culprits()) != 1 {
		t.Fatalf("expected exactly one culprit, got %v", err.Culprits())
	}
}

// Negative control for the test above: the very same transcript, replayed into
// the session it belongs to, is accepted and its ssid adopted. Without this,
// "rejected" would not distinguish a working check from a check that rejects
// everything.
func TestRoundTwoAcceptsItsOwnSession(t *testing.T) {
	ssid := []byte("ssid-of-session-1")
	round := newTestRound2(big.NewInt(1), oldDeclarations(ssid, big.NewInt(1)))

	got, err := round.oldSSIDUnanimous()
	if err != nil {
		t.Fatalf("the party's own session must be accepted, got: %v", err)
	}
	if string(got) != string(ssid) {
		t.Fatalf("expected the declared ssid %q, got %q", ssid, got)
	}
}

// An old committee that does not agree with itself says nothing about WHO lied:
// slot 0 is the array's first element, not a witness. Reporting no culprit is
// deliberate -- see oldSSIDUnanimous.
func TestRoundTwoRejectsANonUnanimousOldCommittee(t *testing.T) {
	msgs := oldDeclarations([]byte("ssid-a"), big.NewInt(1))
	other := oldDeclarations([]byte("ssid-b"), big.NewInt(1))
	msgs[1] = other[1]
	round := newTestRound2(big.NewInt(1), msgs)

	_, err := round.oldSSIDUnanimous()
	if err == nil {
		t.Fatal("a split old committee must not be accepted")
	}
	if !strings.Contains(err.Cause().Error(), ssidNotUnanimousErrText) {
		t.Fatalf("expected the unanimity rejection, got: %v", err.Cause())
	}
	if len(err.Culprits()) != 0 {
		t.Fatalf("a disagreement between messages must name nobody, got %v", err.Culprits())
	}
	if !strings.Contains(err.Cause().Error(), "2 distinct declarations across 2 old slots") {
		t.Fatalf("the partition must be reported for the operator, got: %v", err.Cause())
	}
}

// ValidateBasic does not require Ssid, so the length test in oldSSIDUnanimous is
// what stands between an all-empty old committee and "unanimous" --
// bytes.Equal(nil, nil) is true.
func TestRoundTwoRejectsAnEmptySSIDRatherThanCallingItUnanimous(t *testing.T) {
	round := newTestRound2(big.NewInt(1), oldDeclarations(nil, big.NewInt(1)))

	_, err := round.oldSSIDUnanimous()
	if err == nil {
		t.Fatal("an empty ssid declaration must not be accepted as unanimous")
	}
	if !strings.Contains(err.Cause().Error(), ssidEmptyErrText) {
		t.Fatalf("expected the empty-ssid rejection, got: %v", err.Cause())
	}
	// Single-message-visible fault => the sender is named.
	if len(err.Culprits()) != 1 {
		t.Fatalf("expected exactly one culprit, got %v", err.Culprits())
	}
}

// Defence in depth: round 1 already requires the nonce from every party, so
// reaching round 2 without one means the Parameters were mutated in between.
// There is nothing to compare against, so this must fail rather than proceed.
func TestRoundTwoRefusesWhenThisPartyHasNoNonce(t *testing.T) {
	round := newTestRound2(nil, oldDeclarations([]byte("ssid"), big.NewInt(1)))

	_, err := round.oldSSIDUnanimous()
	if err == nil {
		t.Fatal("a party with no nonce cannot check the old committee and must refuse")
	}
	if !strings.Contains(err.Cause().Error(), sessionNonceMissingErrText) {
		t.Fatalf("expected the missing-nonce rejection, got: %v", err.Cause())
	}
}
