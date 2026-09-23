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
	"math/big"
	"strings"

	"github.com/bnb-chain/tss-lib/v4/crypto/modproof"

	"github.com/bnb-chain/tss-lib/v4/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// The three round-2 SSID rejections. They are distinct strings on purpose: the
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
// Index space. Every old slot j in [0, len(OldParties())) is examined
// by every new party. The loop variable indexes the OLD committee; this party's
// own Index indexes the NEW committee, and the two spaces are unrelated, so the
// old array must never be gated on it.
//
// Attribution. Name a culprit ONLY when the fault is visible in a
// single message; when it is visible only in the disagreement BETWEEN messages,
// refuse to name anyone.
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

	Pi := round.PartyID()
	i := Pi.Index

	// check consistency of SSID. `ssidErr` is deliberately NOT named `err`: the
	// short declarations below (modProof / nTildeModProof / r2msg2) introduce an
	// `error`-typed `err` in this same scope.
	SSID, ssidErr := round.oldSSIDUnanimous()
	if ssidErr != nil {
		return ssidErr
	}
	// Unchanged from before this check was rewritten: the adopted value is the
	// bytes old slot 0 declared. Unanimity makes every slot equal to it.
	round.temp.ssid = SSID

	// 2. "broadcast" "ACK" members of the OLD committee
	r2msg1 := NewDGRound2Message2(
		round.OldParties().IDs().Exclude(round.PartyID()), round.PartyID())
	round.temp.dgRound2Message2s[i] = r2msg1
	round.out <- r2msg1

	// 1.
	// generate Paillier public key E_i, private key and proof
	// generate safe primes for ZKPs later on
	// compute ntilde, h1, h2 (uses safe primes)
	// use the pre-params if they were provided to the LocalParty constructor
	var preParams *keygen.LocalPreParams
	// The first branch is unreachable today and is kept as defence in depth.
	// NewLocalParty copies the caller's LocalPreParams into round.save ONLY when
	// ValidateWithProof() holds, so an incomplete set never arrives here: it is
	// discarded (and logged) at construction, and what round 2 sees is the zero
	// value, for which Validate() is false. Do not read this branch as the place
	// where an incomplete set is rejected.
	if round.save.LocalPreParams.Validate() && !round.save.LocalPreParams.ValidateWithProof() {
		return round.WrapError(
			errors.New("`optionalPreParams` failed to validate; it might have been generated with an older version of tss-lib"))
	} else if round.save.LocalPreParams.ValidateWithProof() {
		preParams = &round.save.LocalPreParams
	} else {
		var err error
		preParams, err = keygen.GeneratePreParams(round.SafePrimeGenTimeout(), round.Concurrency())
		if err != nil {
			return round.WrapError(errors.New("pre-params generation failed"), Pi)
		}
	}
	round.save.LocalPreParams = *preParams
	round.save.NTildej[i] = preParams.NTildei
	round.save.H1j[i], round.save.H2j[i] = preParams.H1i, preParams.H2i

	// generate the dlnproofs for resharing
	h1i, h2i, alpha, beta, p, q, NTildei := preParams.H1i,
		preParams.H2i,
		preParams.Alpha,
		preParams.Beta,
		preParams.P,
		preParams.Q,
		preParams.NTildei
	dlnProof1 := dlnproof.NewDLNProof(round.temp.ssid, h1i, h2i, alpha, p, q, NTildei, round.Rand())
	dlnProof2 := dlnproof.NewDLNProof(round.temp.ssid, h2i, h1i, beta, p, q, NTildei, round.Rand())

	// SECURITY (SRC-2026-926): ModProof is mandatory; the NoProofMod
	// compatibility switch was removed. Always produce the Paillier and NTilde
	// ModProofs. nTildeModProof is a ModProof over this party's own NTilde.
	// SCOPE: the verifier is ProofMod.Verify(Session, N)
	// (crypto/modproof/proof.go#Verify), whose only statement input is the
	// modulus N, so the proof can attest properties of N alone (Blum-integer
	// shape). It does NOT attest that NTilde is a product of safe primes:
	// safe-primality is a property of NTilde's two prime factors — for each
	// factor f, that (f-1)/2 is prime — and those factors never enter Verify,
	// which receives only their product. It also constrains neither h1 nor
	// h2, which are not its inputs. For a peer's ring, <h1> == <h2> is
	// established by the two-directional DLN proof pair instead —
	// dlnproof.Proof.Verify(Session, h1, h2, N) (crypto/dlnproof/proof.go#Verify)
	// — verified at round_4_new_step_2.go#Start, by the VerifyDLNProof1 and
	// VerifyDLNProof2 calls.
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	modProof, err := modproof.NewProof(ContextI, preParams.PaillierSK.N, preParams.PaillierSK.P, preParams.PaillierSK.Q, round.Rand())
	if err != nil {
		return round.WrapError(err, Pi)
	}
	one := big.NewInt(1)
	safePrimeP := new(big.Int).Add(new(big.Int).Lsh(preParams.P, 1), one)
	safePrimeQ := new(big.Int).Add(new(big.Int).Lsh(preParams.Q, 1), one)
	nTildeModProof, err := modproof.NewProof(ContextI, preParams.NTildei, safePrimeP, safePrimeQ, round.Rand())
	if err != nil {
		return round.WrapError(err, Pi)
	}
	r2msg2, err := NewDGRound2Message1(
		round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(),
		&preParams.PaillierSK.PublicKey, modProof, preParams.NTildei, preParams.H1i, preParams.H2i, dlnProof1, dlnProof2, nTildeModProof)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.temp.dgRound2Message1s[i] = r2msg2
	round.out <- r2msg2

	// for this P: SAVE de-commitments, paillier keys for round 2
	round.save.PaillierSK = preParams.PaillierSK
	round.save.PaillierPKs[i] = &preParams.PaillierSK.PublicKey
	round.save.NTildej[i] = preParams.NTildei
	round.save.H1j[i], round.save.H2j[i] = preParams.H1i, preParams.H2i

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if round.ReSharingParams().IsNewCommittee() {
		if _, ok := msg.Content().(*DGRound2Message1); ok {
			return msg.IsBroadcast()
		}
	}
	if round.ReSharingParams().IsOldCommittee() {
		if _, ok := msg.Content().(*DGRound2Message2); ok {
			return msg.IsBroadcast()
		}
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	ret := true
	if round.ReSharingParams().IsOldCommittee() && round.ReSharingParameters.IsNewCommittee() {
		// accept messages from new -> old committee
		for j, msg1 := range round.temp.dgRound2Message2s {
			if round.newOK[j] {
				continue
			}
			if msg1 == nil || !round.CanAccept(msg1) {
				ret = false
				continue
			}
			// accept message from new -> committee
			msg2 := round.temp.dgRound2Message1s[j]
			if msg2 == nil || !round.CanAccept(msg2) {
				ret = false
				continue
			}
			round.newOK[j] = true
		}
	} else if round.ReSharingParams().IsOldCommittee() {
		// accept messages from new -> old committee
		for j, msg := range round.temp.dgRound2Message2s {
			if round.newOK[j] {
				continue
			}
			if msg == nil || !round.CanAccept(msg) {
				ret = false
				continue
			}
			round.newOK[j] = true
		}
	} else if round.ReSharingParams().IsNewCommittee() {
		// accept messages from new -> new committee
		for j, msg := range round.temp.dgRound2Message1s {
			if round.newOK[j] {
				continue
			}
			if msg == nil || !round.CanAccept(msg) {
				ret = false
				continue
			}
			round.newOK[j] = true
		}
	} else {
		return false, round.WrapError(errors.New("this party is not in the old or the new committee"), round.PartyID())
	}
	return ret, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
