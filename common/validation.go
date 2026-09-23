// Copyright © 2026 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

// validationPrimalityRounds sets Miller-Rabin rounds for the composite check
// inside IsUsableUnknownOrderModulus. 30 rounds give ≤ 4^-30 false-positive
// rate against arbitrary composites, well below cryptographic concern.
const validationPrimalityRounds = 30

// IsUsableUnknownOrderModulus reports whether n is a plausible RSA-style
// modulus suitable for use as Paillier N or as the safe-prime product NTilde:
// non-nil, positive, odd, composite (Miller-Rabin), and at least minBits long.
//
// Verifiers must call this on caller-supplied unknown-order moduli before
// running operations like big.Jacobi or modular exponentiation that would
// otherwise panic on degenerate inputs (nil / non-positive / even) or accept
// a prime modulus that trivially satisfies the proof equations.
func IsUsableUnknownOrderModulus(n *big.Int, minBits int) bool {
	if n == nil || n.Sign() != 1 || n.Bit(0) == 0 || n.BitLen() < minBits {
		return false
	}
	return !n.ProbablyPrime(validationPrimalityRounds)
}

// IsCanonicalGenerator reports whether v is a canonical generator-shaped
// element of Z_n* : v ∈ (1, n) and gcd(v, n) = 1. Stricter than
// IsNumberInMultiplicativeGroup, which accepts v == 1 (the identity); use
// this for values like the DLN proof's h1, h2 where v = 1 trivially passes
// the Σ-relation without binding the prover to anything.
//
// Callers should still validate n separately via IsUsableUnknownOrderModulus
// when n is itself attacker-controlled.
func IsCanonicalGenerator(n, v *big.Int) bool {
	if !IsNumberInMultiplicativeGroup(n, v) {
		return false
	}
	return v.Cmp(one) > 0
}

// IsCanonicalPaillierCiphertext reports whether c is a canonical Paillier
// ciphertext under modulus N: c ∈ (0, N²) and gcd(c, N) = 1. The gcd
// condition prevents proofs from using non-units that can leak factors via
// modexp; the upper bound rejects non-canonical representations c + k·N²
// that would otherwise pass purely-modular checks.
//
// Callers should still validate N separately via IsUsableUnknownOrderModulus
// when N is itself attacker-controlled.
func IsCanonicalPaillierCiphertext(c, N *big.Int) bool {
	if c == nil || N == nil || N.Sign() != 1 {
		return false
	}
	NSquared := new(big.Int).Mul(N, N)
	if c.Sign() != 1 || c.Cmp(NSquared) >= 0 {
		return false
	}
	gcd := new(big.Int).GCD(nil, nil, c, N)
	return gcd.Cmp(one) == 0
}
