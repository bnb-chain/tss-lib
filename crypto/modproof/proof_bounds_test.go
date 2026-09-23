// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package modproof

import (
	"crypto/rand"
	"math/big"
	"runtime"
	"testing"
)

// TestVerifyMaxModulusBitLenSitsOnTheBlockTagBoundary pins the derivation of
// verifyMaxModulusBitLen to the code it is derived from, so the constant cannot
// drift away from the reason it holds: sampleYModN tags its 256-bit expansion
// blocks with a single byte, which separates at most 256 of them.
func TestVerifyMaxModulusBitLenSitsOnTheBlockTagBoundary(t *testing.T) {
	const tagValues = 256 // distinct values of []byte{byte(j)}

	blocksAtBound := (verifyMaxModulusBitLen + 255) / 256
	if blocksAtBound != tagValues {
		t.Fatalf("at %d bits sampleYModN uses %d blocks; the one-byte tag separates %d",
			verifyMaxModulusBitLen, blocksAtBound, tagValues)
	}
	blocksAboveBound := (verifyMaxModulusBitLen + 1 + 255) / 256
	if blocksAboveBound <= tagValues {
		t.Fatalf("the bound is not tight: %d bits still needs only %d blocks",
			verifyMaxModulusBitLen+1, blocksAboveBound)
	}
	if verifyMaxModulusBitLen <= verifyMinModulusBitLen {
		t.Fatal("the accepted bit-length window is empty")
	}
}

// oddCompositeAbove returns an odd composite wider than `bits`, built as a
// product so no primality search is needed -- searching for one at this width
// would itself cost the modexps this test is about.
//
//	a = 2^h + 1, b = 2^h + 3 with h = bits/2, both odd,
//	a*b = 2^bits + 4*2^h + 3 > 2^bits, so a*b has bits+1 bits.
func oddCompositeAbove(t *testing.T, bits int) *big.Int {
	t.Helper()
	h := uint(bits / 2)
	a := new(big.Int).Add(new(big.Int).Lsh(one, h), big.NewInt(1))
	b := new(big.Int).Add(new(big.Int).Lsh(one, h), big.NewInt(3))
	n := new(big.Int).Mul(a, b)
	if n.BitLen() != bits+1 || n.Bit(0) == 0 {
		t.Fatalf("oddCompositeAbove produced a %d-bit, parity-%d value", n.BitLen(), n.Bit(0))
	}
	return n
}

// structurallyValidProof builds a ProofMod that clears every per-member check
// in Verify, so that without the bit-length ceiling control would reach the
// sampleYModN loop and the 2*Iterations modexp fan-out.
func structurallyValidProof(t *testing.T, N *big.Int) *ProofMod {
	t.Helper()
	pf := &ProofMod{
		A: new(big.Int).Lsh(one, Iterations),
		B: new(big.Int).Lsh(one, Iterations),
	}
	for w := int64(2); w < 1000 && pf.W == nil; w++ {
		W := big.NewInt(w)
		if new(big.Int).GCD(nil, nil, W, N).Cmp(one) == 0 && big.Jacobi(W, N) != 1 {
			pf.W = W
		}
	}
	if pf.W == nil {
		t.Fatal("could not find a small quadratic non-residue")
	}
	for i := range pf.X {
		pf.X[i], pf.Z[i] = big.NewInt(7), big.NewInt(5)
	}
	return pf
}

// TestVerifyRejectsOversizedModulusWithoutAllocating is the allocation bound.
// N reaches Verify from an exported API and off the wire as SetBytes of one
// protobuf field, and everything sampleYModN builds from it -- the mask, the
// expansion buffer, each of the Iterations candidates -- is O(N.BitLen()) with
// only a floor to constrain it. One Verify call on a 65537-bit modulus (an
// 8 KiB field) measured 8.2 GiB of allocation and 14 seconds before this
// ceiling existed.
func TestVerifyRejectsOversizedModulusWithoutAllocating(t *testing.T) {
	N := oddCompositeAbove(t, verifyMaxModulusBitLen)
	pf := structurallyValidProof(t, N)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	ok := pf.Verify([]byte("session"), N)
	runtime.ReadMemStats(&after)

	if ok {
		t.Fatal("Verify accepted a modulus wider than the sampler is defined for")
	}
	// Measured: 1.5 MiB before the ceiling existed (the Iterations sampler
	// calls alone), 0 after -- the window is tested before anything is built.
	// The Z-goroutines this test never waits for pushed one earlier
	// measurement to 8.2 GiB.
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 256<<10 {
		t.Fatalf("Verify allocated %d bytes (%.1f MiB) for a %d-bit modulus it must reject up front",
			grew, float64(grew)/(1<<20), N.BitLen())
	}
}

// TestVerifyAcceptsTheCanonicalModulusSize is the negative control: the size
// every producer in this library actually emits, and the size the floor is set
// to, must still verify end to end.
func TestVerifyAcceptsTheCanonicalModulusSize(t *testing.T) {
	P, Q := blumPrime(t, verifyMinModulusBitLen/2), blumPrime(t, verifyMinModulusBitLen/2)
	N := new(big.Int).Mul(P, Q)
	if N.BitLen() != verifyMinModulusBitLen {
		t.Fatalf("test modulus is %d bits, wanted %d", N.BitLen(), verifyMinModulusBitLen)
	}

	session := []byte("session")
	pf, err := NewProof(session, N, P, Q, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !pf.Verify(session, N) {
		t.Fatal("an honest proof over a canonical-size modulus was rejected")
	}
}

// blumPrime returns a prime congruent to 3 mod 4, which is what NewProof's
// fourth-root exponent requires of each factor.
func blumPrime(t *testing.T, bits int) *big.Int {
	t.Helper()
	for {
		p, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		if new(big.Int).Mod(p, big.NewInt(4)).Int64() == 3 {
			return p
		}
	}
}
