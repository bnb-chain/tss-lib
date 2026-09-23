// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// primeCongruentToOneModThree returns a prime p of the requested size with
// 3 | p-1, so that Z_p* -- and hence Z_N* for N = p*q -- contains elements of
// order 3. A safe prime cannot do this: p = 2p'+1 gives |Z_p*| = 2p', whose only
// small factor is 2. Keygen does not establish safe-primality of a peer's
// NTilde, so a ring of this shape passes every gate it applies.
func primeCongruentToOneModThree(t *testing.T, bits int) *big.Int {
	t.Helper()
	three := big.NewInt(3)
	for i := 0; i < 200; i++ {
		p := common.GetRandomPrimeInt(rand.Reader, bits)
		if p == nil {
			continue
		}
		if new(big.Int).Mod(new(big.Int).Sub(p, one), three).Sign() == 0 {
			return p
		}
	}
	t.Fatal("could not find a prime congruent to 1 mod 3")
	return nil
}

// smallOrderRing builds (NTilde, h1, h2) with ord(h1) = ord(h2) = 3, h2 = h1^2.
// It passes IsUsableUnknownOrderModulus (odd, composite, >= 2048 bits) and
// IsCanonicalGenerator (h1, h2 in (1, N) and coprime to N), and both DLN
// directions have exponents because each of h1, h2 is a power of the other.
func smallOrderRing(t *testing.T) (NTilde, h1, h2 *big.Int) {
	t.Helper()
	p := primeCongruentToOneModThree(t, 1024)
	q := primeCongruentToOneModThree(t, 1024)
	for p.Cmp(q) == 0 {
		q = primeCongruentToOneModThree(t, 1024)
	}
	NTilde = new(big.Int).Mul(p, q)
	// Raise a random unit to lambda/3, where lambda = lcm(p-1, q-1) is the
	// exponent of Z_N*. The result has order dividing 3, and is non-trivial for
	// most bases because 3 divides lambda. Note that |Z_N*|/3 = (p-1)(q-1)/3 does
	// NOT work: 3 divides both factors, so that exponent is still a common
	// multiple of p-1 and q-1 and sends every element to 1.
	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)
	lambda := new(big.Int).Div(new(big.Int).Mul(pMinus1, qMinus1), new(big.Int).GCD(nil, nil, pMinus1, qMinus1))
	exp := new(big.Int).Div(lambda, big.NewInt(3))
	for i := 0; i < 200; i++ {
		base := common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, NTilde)
		h1 = new(big.Int).Exp(base, exp, NTilde)
		if h1.Cmp(one) != 0 {
			h2 = new(big.Int).Exp(h1, big.NewInt(2), NTilde)
			return NTilde, h1, h2
		}
	}
	t.Fatal("could not find an element of order 3")
	return nil, nil, nil
}

// A ring whose generators have order 3 makes a correctly computed range proof
// land on Z == 1 about a third of the time, and Verify rejects exactly that.
// The ring belongs to the counterparty and so does the verifier, so without a
// check on the proving side the party that merely computed the proof is the one
// reported. ProveRangeAlice must refuse instead, with an error its caller can
// route to the party that supplied the ring.
func TestProveRangeAliceRefusesARingItsOwnVerifierWouldReject(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	NTilde, h1, h2 := smallOrderRing(t)
	assert.True(t, common.IsUsableUnknownOrderModulus(NTilde, verifyMinModulusBitLen),
		"the ring must pass the modulus gate, or the test is not exercising the case")
	assert.True(t, common.IsCanonicalGenerator(NTilde, h1) && common.IsCanonicalGenerator(NTilde, h2),
		"the generators must pass the generator gate, or the test is not exercising the case")

	q := tss.EC().Params().N
	refusals, proofs := 0, 0
	const attempts = 60
	for i := 0; i < attempts; i++ {
		m := common.GetRandomPositiveInt(rand.Reader, q)
		c, r, encErr := sk.EncryptAndReturnRandomness(rand.Reader, m)
		assert.NoError(t, encErr)

		pf, proveErr := ProveRangeAlice(Session, tss.EC(), pk, c, NTilde, h1, h2, m, r, rand.Reader)
		if proveErr != nil {
			assert.True(t, errors.Is(proveErr, ErrCounterpartyRingUnusable),
				"a ring-decided refusal must be routable to the ring's supplier, got %v", proveErr)
			assert.Nil(t, pf, "no proof may be handed out with the error")
			refusals++
			continue
		}
		proofs++
		// Whatever this party does hand out must verify, or the counterparty
		// still gets to report the prover for the counterparty's own ring.
		assert.True(t, pf.Verify(Session, tss.EC(), pk, NTilde, h1, h2, c),
			"a proof that was handed out must be one the counterparty accepts")
	}
	assert.Greater(t, refusals, 0,
		"in %d attempts against an order-3 ring at least one refusal was expected", attempts)
	t.Logf("order-3 ring: %d refused, %d handed out and self-verifying (of %d)", refusals, proofs, attempts)
}

// Negative control for the test above. Refusing everything would satisfy it just
// as well, so an ordinary ring must still produce proofs -- every time.
func TestProveRangeAliceStillProvesAgainstAnOrdinaryRing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	primes := [2]*big.Int{
		common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits),
		common.GetRandomPrimeInt(rand.Reader, testSafePrimeBits),
	}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(rand.Reader, primes)
	assert.NoError(t, err)

	q := tss.EC().Params().N
	for i := 0; i < 20; i++ {
		m := common.GetRandomPositiveInt(rand.Reader, q)
		c, r, encErr := sk.EncryptAndReturnRandomness(rand.Reader, m)
		assert.NoError(t, encErr)
		pf, proveErr := ProveRangeAlice(Session, tss.EC(), pk, c, NTildei, h1i, h2i, m, r, rand.Reader)
		assert.NoError(t, proveErr, "an ordinary ring must not be refused")
		assert.True(t, pf.Verify(Session, tss.EC(), pk, NTildei, h1i, h2i, c))
	}
}

// Bob proves under Alice's ring, so the same asymmetry applies in the other
// direction and ProveBob/ProveBobWC must refuse the same rings.
func TestProveBobRefusesARingItsOwnVerifierWouldReject(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	sk, pk, err := paillier.GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)

	q := tss.EC().Params().N
	x := common.GetRandomPositiveInt(rand.Reader, q)
	y := common.GetRandomPositiveInt(rand.Reader, q)
	c1, _, err := sk.EncryptAndReturnRandomness(rand.Reader, x)
	assert.NoError(t, err)
	c2, r, err := sk.EncryptAndReturnRandomness(rand.Reader, y)
	assert.NoError(t, err)

	// A prime modulus is refused outright by the shape gate, before any secret
	// is committed into it.
	primeRing := common.GetRandomPrimeInt(rand.Reader, 2048)
	_, err = ProveBob(Session, tss.EC(), pk, primeRing, big.NewInt(3), big.NewInt(9), c1, c2, x, y, r, rand.Reader)
	assert.True(t, errors.Is(err, ErrCounterpartyRingUnusable), "got %v", err)

	// So are equal generators: both verifiers reject h1 == h2.
	NTilde, h1, _ := smallOrderRing(t)
	_, err = ProveBob(Session, tss.EC(), pk, NTilde, h1, h1, c1, c2, x, y, r, rand.Reader)
	assert.True(t, errors.Is(err, ErrCounterpartyRingUnusable), "got %v", err)
}

// The two halves of the predicate, stated directly. ringSideValuesUsable is
// deliberately confined to values computed in the counterparty's ring: a
// rejection caused by anything else is the local party's own fault, and naming
// the counterparty for it would be the same error in the opposite direction.
func TestRingPredicates(t *testing.T) {
	NTilde, h1, h2 := smallOrderRing(t)

	assert.True(t, counterpartyRingUsable(NTilde, h1, h2))
	assert.False(t, counterpartyRingUsable(nil, h1, h2))
	assert.False(t, counterpartyRingUsable(NTilde, h1, h1), "h1 == h2 is rejected by both verifiers")
	assert.False(t, counterpartyRingUsable(NTilde, one, h2), "the identity is not a generator")
	assert.False(t, counterpartyRingUsable(common.GetRandomPrimeInt(rand.Reader, 2048), h1, h2),
		"a prime modulus has known order")
	assert.False(t, counterpartyRingUsable(big.NewInt(15), h1, h2), "an undersized modulus is rejected")

	assert.True(t, ringSideValuesUsable(NTilde, h1, h2))
	assert.False(t, ringSideValuesUsable(NTilde, one), "a ring-side value of 1 binds nothing")
	assert.False(t, ringSideValuesUsable(NTilde, h1, one))
	assert.False(t, ringSideValuesUsable(NTilde, nil))
	assert.False(t, ringSideValuesUsable(NTilde, big.NewInt(0)))
	assert.False(t, ringSideValuesUsable(NTilde, NTilde), "values must lie inside the ring")
}
