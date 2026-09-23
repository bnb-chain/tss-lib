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

	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
	"github.com/btcsuite/btcd/btcec/v2"
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
		EcdsaPubX: []byte{1}, EcdsaPubY: []byte{2}, VCommitment: []byte{3},
		Ssid: []byte{4}, SessionNonceHash: []byte{5},
	}
	if !full.ValidateBasic() {
		t.Fatal("a complete message must still validate")
	}
	missing := &DGRound1Message{
		EcdsaPubX: []byte{1}, EcdsaPubY: []byte{2}, VCommitment: []byte{3},
		Ssid: []byte{4},
	}
	if missing.ValidateBasic() {
		t.Fatal("a message with no session nonce hash must be rejected")
	}
}

// Neither field had an upper bound. Both are produced as
// common.SHA512_256i(...).Bytes(), so 32 is the exact width a conforming sender
// can reach -- a derived bound rather than a chosen one. It matters for the
// ssid because round 2 adopts it into round.temp.ssid, which then prefixes the
// Session of every zero-knowledge proof in the run: a declared length is a
// length this party re-hashes on each of them.
func TestDGRound1MessageBoundsTheSessionFields(t *testing.T) {
	atWidth := func(n int) *DGRound1Message {
		return &DGRound1Message{
			EcdsaPubX: []byte{1}, EcdsaPubY: []byte{2}, VCommitment: []byte{3},
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
		EcdsaPubX: []byte{1}, EcdsaPubY: []byte{2}, VCommitment: []byte{3},
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
// that used to get all the way to round 2.
func TestNewCommitteePartyWithoutNonceFailsInRoundOne(t *testing.T) {
	oldIDs := tss.GenerateTestPartyIDs(2)
	newIDs := tss.GenerateTestPartyIDs(2, 2)
	params := tss.NewReSharingParameters(btcec.S256(), tss.NewPeerContext(oldIDs),
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
