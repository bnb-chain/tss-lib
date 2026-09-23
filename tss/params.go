// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"strings"
	"time"
)

type (
	Parameters struct {
		ec                  elliptic.Curve
		partyID             *PartyID
		parties             *PeerContext
		partyCount          int
		threshold           int
		concurrency         int
		safePrimeGenTimeout time.Duration
		// sessionNonce provides per-session SSID uniqueness for GG20 session binding.
		// The caller MUST set it — to a value agreed upon by all parties, e.g. a
		// coordinator-assigned session ID — before starting round 1. Every party
		// that derives an SSID fails round 1 without it, and none of them has a
		// fallback: ECDSA and EdDSA keygen, ECDSA and EdDSA signing, and the old
		// committee in ECDSA resharing. A value the library picks for itself is
		// one no participant agreed to and one it cannot check for freshness.
		//
		// Two paths do not read it, because they derive no SSID at all: the new
		// committee's first round in ECDSA resharing, and EdDSA resharing.
		sessionNonce *big.Int
		// NOTE: the former noProofMod and noProofFac legacy-compatibility flags
		// have both been removed — ModProof (SRC-2026-926) and FacProof are now
		// verified unconditionally in keygen and resharing.
		//
		// The two proofs are not interchangeable, which is why neither may be
		// skipped: they attest to different properties of a peer's modulus and
		// neither implies the other. See crypto/facproof and crypto/modproof
		// for the scope of each.
		// random sources
		partialKeyRand, rand io.Reader
	}

	ReSharingParameters struct {
		*Parameters
		newParties    *PeerContext
		newPartyCount int
		newThreshold  int
	}
)

const (
	defaultSafePrimeGenTimeout = 5 * time.Minute
)

// Exported, used in `tss` client.
//
// Panics on invalid threshold / partyCount inputs (threshold < 1,
// partyCount < 2, or threshold >= partyCount). These constraints come
// from Shamir VSS — a valid (t, n) threshold scheme requires
// 1 <= t < n with n >= 2. Invalid combinations would otherwise surface
// as opaque panics deep in protocol execution; failing here gives
// callers an immediate, clear signal.
func NewParameters(ec elliptic.Curve, ctx *PeerContext, partyID *PartyID, partyCount, threshold int) *Parameters {
	if partyCount < 2 {
		panic(fmt.Errorf("NewParameters: partyCount must be >= 2, got %d", partyCount))
	}
	if threshold < 1 {
		panic(fmt.Errorf("NewParameters: threshold must be >= 1, got %d", threshold))
	}
	if threshold >= partyCount {
		panic(fmt.Errorf("NewParameters: threshold must be < partyCount, got t=%d n=%d",
			threshold, partyCount))
	}
	// Reject PartyID sets whose keys collide modulo the curve order q.
	// SortPartyIDs dedups raw bytes, but Lagrange arithmetic downstream
	// (eddsa/ecdsa signing prepare.go, vss.Shares.ReConstruct) treats
	// ID as `ID mod q`. A malicious party registering key = honest_key + q
	// passes SortPartyIDs but causes `ModInverse((kj - ki) mod q, q)` to
	// hit a zero divisor and panic at signing time. Fail here instead so
	// the bad configuration never reaches a protocol round.
	if ctx != nil {
		assertDistinctIDsModQ(ec, ctx.IDs())
	}
	return &Parameters{
		ec:                  ec,
		parties:             ctx,
		partyID:             partyID,
		partyCount:          partyCount,
		threshold:           threshold,
		concurrency:         runtime.GOMAXPROCS(0),
		safePrimeGenTimeout: defaultSafePrimeGenTimeout,
		partialKeyRand:      rand.Reader,
		rand:                rand.Reader,
	}
}

func (params *Parameters) EC() elliptic.Curve {
	return params.ec
}

func (params *Parameters) Parties() *PeerContext {
	return params.parties
}

func (params *Parameters) PartyID() *PartyID {
	return params.partyID
}

func (params *Parameters) PartyCount() int {
	return params.partyCount
}

func (params *Parameters) Threshold() int {
	return params.threshold
}

func (params *Parameters) Concurrency() int {
	return params.concurrency
}

func (params *Parameters) SafePrimeGenTimeout() time.Duration {
	return params.safePrimeGenTimeout
}

// The concurrency level must be >= 1.
func (params *Parameters) SetConcurrency(concurrency int) {
	params.concurrency = concurrency
}

func (params *Parameters) SetSafePrimeGenTimeout(timeout time.Duration) {
	params.safePrimeGenTimeout = timeout
}

func (params *Parameters) PartialKeyRand() io.Reader {
	return params.partialKeyRand
}

func (params *Parameters) Rand() io.Reader {
	return params.rand
}

func (params *Parameters) SetPartialKeyRand(rand io.Reader) {
	params.partialKeyRand = rand
}

func (params *Parameters) SetRand(rand io.Reader) {
	params.rand = rand
}

// SessionNonce returns the per-session nonce for SSID uniqueness.
// Returns nil if not set.
func (params *Parameters) SessionNonce() *big.Int {
	return params.sessionNonce
}

// SetSessionNonce sets a per-session nonce that all parties must agree on.
// This value is mixed into the SSID to provide GG20 session binding, preventing
// cross-session proof replay attacks. All parties in the same session MUST use
// the same nonce value. The caller is responsible for coordinating this.
//
// It must be set before Start(); every round 1 that derives an SSID fails
// otherwise. Note that Parameters is per party, not per execution: a caller
// that keeps one Parameters object around for the lifetime of a party has to
// set a fresh nonce for every execution it runs, since the previous value
// stays behind otherwise.
//
// SECURITY REQUIREMENTS. Freshness above is not merely housekeeping; together
// with secrecy it is what the binding rests on, and both are the caller's
// responsibility. This library does not enforce either.
//
//   - The nonce's PREIMAGE MUST BE SECRET. Only its SHA512_256 digest travels on
//     the wire, which does not make the preimage public knowledge. Anyone holding
//     the preimage can set the same nonce on an instance of their own.
//   - The nonce MUST BE UNIQUE PER RESHARING INSTANCE, not merely per logical
//     session. The binding's granularity is the nonce, so two instantiations that
//     share one are indistinguishable to the protocol.
//   - This library keeps NO cross-instance record of consumed nonces. Reusing one
//     lets a passively captured old-committee transcript be adopted by a second,
//     independent new-committee instance, which then derives share material for
//     the same public key without any live old-committee party taking part. The
//     round-2 binding check does not catch this: it compares the nonce, and the
//     nonce matches.
//
// Callers that cannot guarantee both properties should treat the transcript
// itself as key material and protect it accordingly.
func (params *Parameters) SetSessionNonce(nonce *big.Int) {
	params.sessionNonce = nonce
}

// ----- //

// Exported, used in `tss` client
//
// Panics if the old and the new committee share a member. Re-sharing "in
// place" — the same party sitting in both committees — is not a supported
// configuration: no round in either the ECDSA or the EdDSA re-sharing protocol
// is written for a party that is simultaneously a sender and a receiver, and
// the "ok" trackers of five rounds are pre-set on the SENDER-role predicate
// (see doc/maintenance-invariants.md). Membership is decided by the party KEY,
// which is the only identity the protocol shares across the two committees —
// not by Index (the two committees have independent index spaces and legally
// both start at 0), not by the key's residue mod q (`k` and `k + q` are two
// different parties here, whatever the Lagrange arithmetic later does with
// them), and not by position in the sorted order.
//
// SCOPE: this is a CONSTRUCTION-TIME check and nothing more. It says nothing
// about the state of the two PeerContexts later on: NewPeerContext keeps the
// caller's slice by reference, PeerContext.SetIDs rewrites it in place, and the
// *PartyID values stay owned by the caller. A caller that mutates a context
// after construction can still produce a dual-role party; the round-1 guards in
// ecdsa/resharing and eddsa/resharing are the defence in depth for that case.
func NewReSharingParameters(ec elliptic.Curve, ctx, newCtx *PeerContext, partyID *PartyID, partyCount, threshold, newPartyCount, newThreshold int) *ReSharingParameters {
	params := NewParameters(ec, ctx, partyID, partyCount, threshold)
	// Apply the same mod-q distinctness check to the new committee. The
	// new committee participates in VSS and Lagrange too, so a collision
	// inside it would be just as fatal as one in the old committee.
	if newCtx != nil {
		assertDistinctIDsModQ(ec, newCtx.IDs())
	}
	assertDisjointCommittees(ctx, newCtx)
	return &ReSharingParameters{
		Parameters:    params,
		newParties:    newCtx,
		newPartyCount: newPartyCount,
		newThreshold:  newThreshold,
	}
}

// CommitteeOverlapKeys returns the party keys that appear in BOTH committees,
// in old-committee order, de-duplicated. An empty result means the two
// committees are disjoint and NewReSharingParameters will accept them.
//
// Callers who would rather branch than catch a panic can use this first.
// Two parties are the same party iff their keys are equal as integers; `Index`
// and the mod-q residue of the key are deliberately not consulted.
//
// A nil context yields no overlap: a caller who passes nil has not described a
// committee, which matches how NewParameters treats a nil PeerContext.
func CommitteeOverlapKeys(oldCtx, newCtx *PeerContext) []*big.Int {
	if oldCtx == nil || newCtx == nil {
		return nil
	}
	return committeeOverlapKeys(oldCtx.IDs(), newCtx.IDs())
}

// partyKeyID returns the party's exact key as a canonical hex string, plus
// whether it could be read at all.
//
// KeyInt() is promoted through the embedded *MessageWrapper_PartyID, so
// `id.KeyInt()` dereferences that pointer — testing `id.KeyInt() == nil` would
// fault on exactly the malformed PartyID it is trying to skip (and would never
// be true anyway, since SetBytes(nil) returns 0, not nil). Test the embedded
// pointer explicitly first, the same way ValidateBasic does.
func partyKeyID(id *PartyID) (string, bool) {
	if id == nil || id.MessageWrapper_PartyID == nil {
		return "", false
	}
	return id.KeyInt().Text(16), true
}

func committeeOverlapKeys(oldIDs, newIDs []*PartyID) []*big.Int {
	inNew := make(map[string]struct{}, len(newIDs))
	for _, id := range newIDs {
		if k, ok := partyKeyID(id); ok {
			inNew[k] = struct{}{}
		}
	}
	overlap := make([]*big.Int, 0, len(oldIDs))
	reported := make(map[string]struct{}, len(oldIDs))
	for _, id := range oldIDs {
		k, ok := partyKeyID(id)
		if !ok {
			continue
		}
		if _, dup := reported[k]; dup {
			continue
		}
		if _, both := inNew[k]; both {
			reported[k] = struct{}{}
			overlap = append(overlap, id.KeyInt())
		}
	}
	return overlap
}

// assertDisjointCommittees panics if any party key is present in both
// committees. See NewReSharingParameters for why this is fatal and for the
// (construction-time only) scope of the guarantee.
func assertDisjointCommittees(oldCtx, newCtx *PeerContext) {
	overlap := CommitteeOverlapKeys(oldCtx, newCtx)
	if len(overlap) == 0 {
		return
	}
	hexes := make([]string, len(overlap))
	for i, k := range overlap {
		hexes[i] = k.Text(16)
	}
	panic(fmt.Errorf("NewReSharingParameters: the old and the new committee must be disjoint; re-sharing in place is not a supported configuration; %d party key(s) are in both committees: [%s]",
		len(overlap), strings.Join(hexes, " ")))
}

// assertDistinctIDsModQ panics if any two ids share the same `KeyInt() mod q`
// residue, or if any single id reduces to 0 mod q.
//
// Mod-q collisions would later trigger a `ModInverse(0, q)` zero-divisor
// panic deep inside signing / VSS reconstruction.
//
// A zero residue is fatal in a different way: in Shamir secret sharing
// the polynomial is evaluated at the party's key, and f(0) is the
// shared secret itself. A party with `KeyInt() mod q == 0` would,
// post-Lagrange, either receive the raw secret as their share (if
// keygen flowed through `vss.Create` directly without `CheckIndexes`)
// or cause peer Lagrange coefficients to collapse to 0 / nil at
// signing time (see `ecdsa/signing/prepare.go` `iota = ksc *
// ModInverse(...)` — when `ksc mod q == 0`, `iota == 0`, and
// `bigWj.ScalarMult(0)` returns nil, panicking on the next chained
// op). vss.Create already rejects zero IDs via `CheckIndexes`, but
// rejecting here as well gives a clear, locally-attributable error
// and defends external direct-API consumers that bypass `vss.Create`
// (e.g. loading legacy `LocalPartySaveData` and going straight to
// signing).
func assertDistinctIDsModQ(ec elliptic.Curve, ids []*PartyID) {
	if ec == nil {
		return
	}
	q := ec.Params().N
	seen := make(map[string]string, len(ids))
	for _, id := range ids {
		// Test the embedded pointer, not `id.KeyInt() == nil` -- see partyKeyID
		// above for why that test both faults on the value it means to skip and
		// can never be true.
		if id == nil || id.MessageWrapper_PartyID == nil {
			continue
		}
		residueBig := new(big.Int).Mod(id.KeyInt(), q)
		if residueBig.Sign() == 0 {
			panic(fmt.Errorf("NewParameters: party key %s is congruent to 0 mod q; this would reveal the Shamir secret as the party's share and would cause zero Lagrange coefficients at signing time",
				id.KeyInt().Text(16)))
		}
		residue := residueBig.Text(16)
		if prior, exists := seen[residue]; exists {
			panic(fmt.Errorf("NewParameters: party keys %s and %s collide mod q (residue 0x%s); the Lagrange interpolation would hit a zero divisor at signing time",
				prior, id.KeyInt().Text(16), residue))
		}
		seen[residue] = id.KeyInt().Text(16)
	}
}

// The old committee lives in the EMBEDDED *Parameters, so every "Old" reader
// below goes through a promoted field or method and dereferences that pointer.
// Nothing sets it: `ReSharingParameters{}` and `json.Unmarshal("{}", &rp)` both
// leave it nil, and NewReSharingParameters is not on either path. The "New"
// readers need no such guard -- newParties / newPartyCount / newThreshold are
// ReSharingParameters' own fields.
//
// An absent *Parameters describes no old committee at all, so each reader
// answers the way the rest of the package already answers for an undescribed
// committee: no roster (PeerContext.IDs on a nil context), and a count of zero.

func (rgParams *ReSharingParameters) OldParties() *PeerContext {
	if rgParams.Parameters == nil {
		return nil
	}
	return rgParams.Parties() // wr use the original method for old parties
}

func (rgParams *ReSharingParameters) OldPartyCount() int {
	if rgParams.Parameters == nil {
		return 0
	}
	return rgParams.partyCount
}

func (rgParams *ReSharingParameters) NewParties() *PeerContext {
	return rgParams.newParties
}

func (rgParams *ReSharingParameters) NewPartyCount() int {
	return rgParams.newPartyCount
}

func (rgParams *ReSharingParameters) NewThreshold() int {
	return rgParams.newThreshold
}

func (rgParams *ReSharingParameters) OldAndNewParties() []*PartyID {
	return append(rgParams.OldParties().IDs(), rgParams.NewParties().IDs()...)
}

func (rgParams *ReSharingParameters) OldAndNewPartyCount() int {
	return rgParams.OldPartyCount() + rgParams.NewPartyCount()
}

// isInCommittee reports whether this party's key appears in the given roster.
//
// rgParams.partyID is itself a promoted field, so this has the same nil
// embedded *Parameters exposure as the "Old" readers above and needs the same
// guard: a party the caller never described matches nobody, which is the
// answer already given for a PartyID whose key cannot be read.
//
// Nothing validates rgParams.partyID or either PeerContext at construction time:
// NewParameters checks partyCount, threshold and the roster's residues, but it
// never looks at partyID, and it stores a nil context unconditionally. The
// resharing constructor calls IsOldCommittee before any round runs, so
// BaseStart's ValidateBasic is too late to help here. Both malformed inputs
// therefore have to be tolerated at this level, and "not in the committee" is
// the honest answer for each: a party with no readable key matches nobody, and
// an absent roster contains nobody.
//
// Keys are compared as canonical hex, which is equality on the same integers
// partyKeyID reads -- so this agrees with the previous KeyInt().Cmp comparison
// on every well-formed input, and simply declines to fault on the rest.
func (rgParams *ReSharingParameters) isInCommittee(ctx *PeerContext) bool {
	if rgParams.Parameters == nil {
		return false
	}
	self, ok := partyKeyID(rgParams.partyID)
	if !ok {
		return false
	}
	for _, Pj := range ctx.IDs() {
		if key, ok := partyKeyID(Pj); ok && key == self {
			return true
		}
	}
	return false
}

func (rgParams *ReSharingParameters) IsOldCommittee() bool {
	// Via OldParties(), not the promoted `parties` field: the argument is
	// evaluated before isInCommittee's own guard can run.
	return rgParams.isInCommittee(rgParams.OldParties())
}

func (rgParams *ReSharingParameters) IsNewCommittee() bool {
	return rgParams.isInCommittee(rgParams.newParties)
}
