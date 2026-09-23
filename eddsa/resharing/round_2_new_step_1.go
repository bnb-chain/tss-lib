// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/bnb-chain/tss-lib/v4/tss"
)

// The round-2 SSID rejections. They are distinct strings on purpose: the
// empty-declaration rejection is the only one that names a culprit, so a caller
// (or a test) must be able to tell it apart from the disagreement rejection
// without parsing the culprit list.
const (
	ssidEmptyErrText = "round 2: an old committee member declared an empty ssid " +
		"(DGRound1Message.ValidateBasic does not require the ssid field)"
	ssidNotUnanimousErrText = "round 2: the old committee's ssid declarations are not unanimous"
	ssidMissingErrText      = "round 2: an old committee round-1 message is missing or of the wrong type"
	// The new committee cannot recompute the old committee's ssid -- its
	// pre-image is the OLD save data. This is the one value in the round-1
	// message it can check against something of its own.
	sessionNonceMismatchErrText = "round 2: an old committee member declared a session " +
		"nonce hash that does not match this party's own session nonce; the two " +
		"committees are not in the same session"
	sessionNonceMissingErrText = "round 2: this party has no session nonce, so it cannot " +
		"check that the old committee is in the same session; call Parameters.SetSessionNonce"
)

// oldSSIDUnanimous returns the ssid that the WHOLE old committee declared, or an
// error if it did not declare exactly one value.
//
// Index space. Every old slot j in [0, len(OldParties())) is examined by every
// new party. The loop variable indexes the OLD committee; this party's own
// Index indexes the NEW committee, and the two spaces are unrelated, so the old
// array must never be gated on it.
//
// Attribution. Name a culprit ONLY when the fault is visible in a single
// message; when it is visible only in the disagreement BETWEEN messages, refuse
// to name anyone.
//   - An empty declaration is single-message-visible => the sender is named.
//   - A disagreement is not. It says the old committee does not agree; it does
//     not say who lied. Slot 0 is not a witness, only the array's first element,
//     so "everyone must equal slot 0, blame whoever differs" blames an honest
//     party whenever slot 0 is the liar. Majority/plurality is no better here:
//     tss.NewParameters only requires 1 <= t < n and round_1_old_step_1.go only
//     requires Threshold()+1 <= len(ks), so n_old = t+1 is a legal committee, and
//     there the t tolerated corrupt parties are a strict majority. At that size
//     ejecting the named "culprit" leaves t shares, which round_1_old_step_1.go's
//     `t+1 > len(ks)` gate turns into a permanent inability to re-share.
//     The disagreement is therefore reported with NO culprits, and the partition
//     is written into the message so an operator can see it.
//
// The emptiness test runs BEFORE any comparison, and it is a length test, not a
// nil test: DGRound1Message.ValidateBasic (messages.go) does not require Ssid,
// and bytes.Equal(nil, nil) is true, so an old committee that all declared
// nothing would otherwise be laundered into "unanimous".
//
// Callers get []byte, *tss.Error — not error — because a *tss.Error already
// carries the round, the victim and the culprit list.
func (round *round2) oldSSIDUnanimous() ([]byte, *tss.Error) {
	// This party's own expectation, derived from its OWN Parameters -- never
	// from anything on the wire.
	//
	// The nil/non-positive branch is defence in depth: round 1 already requires
	// a positive nonce from EVERY party, old committee or new, before any
	// message is sent, so a party reaching round 2 without one has had its
	// Parameters mutated in between. Failing here rather than proceeding is
	// still the right answer -- without a nonce there is nothing to compare the
	// old committee's declaration against.
	nonce := round.Params().SessionNonce()
	if nonce == nil || nonce.Sign() <= 0 {
		return nil, round.WrapError(errors.New(sessionNonceMissingErrText))
	}
	want := sessionNonceHash(nonce)

	oldIDs := round.OldParties().IDs()
	declared := make([][]byte, len(oldIDs))
	for j := range oldIDs {
		msg := round.temp.dgRound1Messages[j]
		if msg == nil {
			// Local state fault, not a peer's doing: round 2 cannot start until
			// every oldOK[j] is set. No culprit.
			return nil, round.WrapError(errors.New(ssidMissingErrText))
		}
		r1msg, ok := msg.Content().(*DGRound1Message)
		if !ok {
			return nil, round.WrapError(errors.New(ssidMissingErrText), msg.GetFrom())
		}
		// Check the session binding BEFORE anything is adopted. This is the
		// whole point of the field: unanimity below compares the old committee's
		// declarations only to EACH OTHER, so a complete transcript captured
		// from another session is unanimous with itself and passes.
		// Single-message-visible => name the sender, per this function's rule.
		if !bytes.Equal(r1msg.UnmarshalSessionNonceHash(), want) {
			return nil, round.WrapError(errors.New(sessionNonceMismatchErrText), msg.GetFrom())
		}
		ssidJ := r1msg.UnmarshalSSID()
		if len(ssidJ) == 0 {
			// Name the sender of THAT message, never oldIDs[j]: nothing in this
			// library binds a sender's From.Index to its From.Key, so the roster
			// entry at j need not be the party that sent the message.
			return nil, round.WrapError(errors.New(ssidEmptyErrText), msg.GetFrom())
		}
		declared[j] = ssidJ
	}
	for j := 1; j < len(declared); j++ {
		if !bytes.Equal(declared[0], declared[j]) {
			return nil, round.WrapError(errors.New(
				ssidNotUnanimousErrText + "; " + describeSSIDSplit(declared)))
		}
	}
	return declared[0], nil
}

// describeSSIDSplit renders the partition of the old committee by declared ssid.
// Groups appear in ascending order of their lowest old slot, so the text is a
// function of the received messages alone: every new party produces the same
// bytes, and nothing about the reporting party's own index leaks into it.
func describeSSIDSplit(declared [][]byte) string {
	values := make([][]byte, 0, len(declared))
	groups := make([][]int, 0, len(declared))
	for j, d := range declared {
		placed := false
		for g := range values {
			if bytes.Equal(values[g], d) {
				groups[g] = append(groups[g], j)
				placed = true
				break
			}
		}
		if !placed {
			values = append(values, d)
			groups = append(groups, []int{j})
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d distinct declarations across %d old slots:", len(values), len(declared))
	for g := range values {
		sb.WriteString(" [old slots")
		for _, j := range groups[g] {
			fmt.Fprintf(&sb, " %d", j)
		}
		fmt.Fprintf(&sb, " -> %s]", hex.EncodeToString(values[g]))
	}
	return sb.String()
}

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allOldOK()

	if !round.ReSharingParams().IsNewCommittee() {
		return nil
	}

	// Check the session binding BEFORE this party ACKs anything. `ssidErr` is
	// deliberately not named `err`: an ACK is this party's statement that it
	// accepted the old committee's round 1, and it must not be sent for a
	// transcript belonging to a different execution.
	SSID, ssidErr := round.oldSSIDUnanimous()
	if ssidErr != nil {
		return ssidErr
	}
	// The adopted value is the bytes old slot 0 declared. Unanimity makes every
	// slot equal to it. Nothing downstream in this package consumes ssid today:
	// it is held so that a future proof context, and any operator reading the
	// party's state, has the execution's own identifier rather than nothing.
	round.temp.ssid = SSID

	round.allNewOK()

	Pi := round.PartyID()
	i := Pi.Index

	// 1. "broadcast" "ACK" members of the OLD committee
	r2msg := NewDGRound2Message(round.OldParties().IDs(), Pi)
	round.temp.dgRound2Messages[i] = r2msg
	round.out <- r2msg

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*DGRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	// only the old committee receive in this round
	if !round.ReSharingParams().IsOldCommittee() {
		return true, nil
	}

	ret := true
	// accept messages from new -> old committee
	for j, msg := range round.temp.dgRound2Messages {
		if round.newOK[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.newOK[j] = true
	}

	return ret, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
