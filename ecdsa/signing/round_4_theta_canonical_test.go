// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// Round 4 sums every peer's round-3 theta and inverts the total. The peers'
// values arrive from the wire, and until they are checked the sum silently
// normalises whatever it is handed: a value at or above the curve order is
// reduced rather than refused, and an arbitrarily long byte string is
// materialised before that reduction discards it.
//
// An honest theta cannot trip either test. Round 3 produces it through
// modN.Add, so it is always in [0, q) and its encoding is at most the order's
// byte length. The tests below pin that both directions hold: honest values go
// through untouched, and each malformed shape is refused with the sender named.
//
// The bound is the curve order, which is why it lives here and not in
// SignRound3Message.ValidateBasic: that method takes no arguments and the curve
// is supplied by the caller. The EdDSA side caps its own field with a constant
// because that protocol is single-curve; ECDSA signing is not.

// newRound4UnderTest builds a round 4 on honest local state, with each peer's
// round-3 broadcast supplied by peerTheta. Only the state round 4 reads is
// populated; this does not stand in for a real signing session.
func newRound4UnderTest(t *testing.T, peerTheta func(j int) *big.Int) (*round4, tss.SortedPartyIDs) {
	t.Helper()

	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	assert.NoError(t, err, "should load keygen fixtures")

	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(signPIDs), signPIDs[0], len(signPIDs), testThreshold)
	params.SetSessionNonce(big.NewInt(1))

	ec := params.EC()
	q := ec.Params().N

	gamma := common.GetRandomPositiveInt(params.PartialKeyRand(), q)
	pointGamma := crypto.ScalarBaseMult(ec, gamma)
	cmt := commitments.NewHashCommitment(params.Rand(), pointGamma.X(), pointGamma.Y())

	temp := &localTempData{}
	temp.signRound3Messages = make([]tss.ParsedMessage, len(signPIDs))
	temp.signRound4Messages = make([]tss.ParsedMessage, len(signPIDs))
	temp.theta = common.GetRandomPositiveInt(params.PartialKeyRand(), q)
	temp.gamma = gamma
	temp.pointGamma = pointGamma
	temp.deCommit = cmt.D
	temp.ssid = []byte("round-4-theta-canonical-test")

	for j, Pj := range signPIDs {
		if j == params.PartyID().Index {
			continue
		}
		temp.signRound3Messages[j] = NewSignRound3Message(Pj, peerTheta(j))
	}

	b := &base{
		Parameters: params,
		key:        &keys[0],
		data:       &common.SignatureData{},
		temp:       temp,
		out:        make(chan tss.Message, len(signPIDs)*2),
		end:        make(chan *common.SignatureData, 1),
		ok:         make([]bool, len(signPIDs)),
	}
	return &round4{&round3{&round2{&round1{b}}}}, signPIDs
}

func mentionsTheta(err *tss.Error) bool {
	if err == nil {
		return false
	}
	c := strings.ToLower(err.Cause().Error())
	return strings.Contains(c, "theta is not a canonical scalar") ||
		strings.Contains(c, "theta is longer than the curve order")
}

// Negative control: the guard must be invisible to an honest round. Every peer
// sends a reduced theta, which is the only shape round 3 can produce.
func TestRound4AcceptsHonestTheta(t *testing.T) {
	setUp("info")

	q := tss.S256().Params().N
	round, _ := newRound4UnderTest(t, func(j int) *big.Int {
		return new(big.Int).Sub(q, big.NewInt(int64(j)+1)) // in [0, q), and near the top of the range
	})

	tssErr := round.Start()
	assert.False(t, mentionsTheta(tssErr),
		"an honest theta must not be refused by the canonicality guard, got %v", tssErr)
	assert.Nil(t, tssErr, "the honest round must complete, got %v", tssErr)
	assert.NotNil(t, round.temp.thetaInverse, "the honest round must store an inverse")
}

// A peer that does not reduce its theta must be refused, and named.
func TestRound4RefusesNonCanonicalTheta(t *testing.T) {
	setUp("info")

	q := tss.S256().Params().N
	const culpritIdx = 1

	round, signPIDs := newRound4UnderTest(t, func(j int) *big.Int {
		if j == culpritIdx {
			return new(big.Int).Set(q) // congruent to zero, but not reduced
		}
		return big.NewInt(int64(j) + 1)
	})

	tssErr := round.Start()
	if !assert.NotNil(t, tssErr, "a theta at the curve order must be refused") {
		return
	}
	assert.Contains(t, tssErr.Cause().Error(), "theta is not a canonical scalar")
	if !assert.Len(t, tssErr.Culprits(), 1, "exactly the sender must be named, got %v", tssErr.Culprits()) {
		return
	}
	assert.Equal(t, signPIDs[culpritIdx].Id, tssErr.Culprits()[0].Id,
		"the party that sent the non-canonical theta must be named")
	assert.Nil(t, round.temp.thetaInverse, "no inverse may be stored once the round refuses")
}

// A peer that sends more bytes than the order needs must be refused before the
// value is materialised, and named.
func TestRound4RefusesOverlongTheta(t *testing.T) {
	setUp("info")

	const culpritIdx = 1
	overlong := new(big.Int).Lsh(big.NewInt(1), 4096) // 513 bytes, far beyond a secp256k1 scalar

	round, signPIDs := newRound4UnderTest(t, func(j int) *big.Int {
		if j == culpritIdx {
			return overlong
		}
		return big.NewInt(int64(j) + 1)
	})

	tssErr := round.Start()
	if !assert.NotNil(t, tssErr, "an over-long theta must be refused") {
		return
	}
	assert.Contains(t, tssErr.Cause().Error(), "theta is longer than the curve order")
	if !assert.Len(t, tssErr.Culprits(), 1, "exactly the sender must be named, got %v", tssErr.Culprits()) {
		return
	}
	assert.Equal(t, signPIDs[culpritIdx].Id, tssErr.Culprits()[0].Id,
		"the party that sent the over-long theta must be named")
}

// The largest honest value, q-1, sits one below the refusal boundary and must
// still be accepted. This pins the guard to > q-1 rather than >= q-1.
func TestRound4AcceptsThetaAtUpperBound(t *testing.T) {
	setUp("info")

	q := tss.S256().Params().N
	qMinusOne := new(big.Int).Sub(q, big.NewInt(1))

	round, _ := newRound4UnderTest(t, func(j int) *big.Int { return qMinusOne })

	tssErr := round.Start()
	assert.False(t, mentionsTheta(tssErr),
		"q-1 is a legal scalar and must not be refused, got %v", tssErr)
	assert.Nil(t, tssErr, "the round must complete on q-1, got %v", tssErr)
}
