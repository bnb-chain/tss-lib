// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package facproof

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
)

const (
	ProofFacBytesParts = 11
	// verifyMinModulusBitLen matches the keygen wire-format check for
	// Paillier N and NTilde (paillierBitsLen = 2048).
	verifyMinModulusBitLen = 2048
	// fsDomainTag is the Fiat-Shamir domain separator prepended to the
	// caller-supplied Session for every challenge derivation in this
	// package. Cross-proof transcript collisions are already statistically
	// implausible because each proof type hashes a different arity of
	// big.Int inputs (length-encoded by SHA512_256i_TAGGED), but explicit
	// type tagging makes the domain separation visible and audit-friendly.
	fsDomainTag = "tss-lib.v4.facproof"
)

// fsSession returns the per-proof-type tagged Session bytes. Wire-incompat
// with v3 by design (v4 module bump consumes this break).
func fsSession(Session []byte) []byte {
	return append([]byte(fsDomainTag+"|"), Session...)
}

type (
	ProofFac struct {
		P, Q, A, B, T, Sigma, Z1, Z2, W1, W2, V *big.Int
	}
)

// SCOPE OF THIS PROOF — read before relying on it for small-factor exclusion.
//
// Verify establishes that the prover knows a two-part factorisation N0 = A·B
// with both parts inside the range window (|A|,|B| < q³·√N0, enforced via
// Z1/Z2). It does NOT establish that A and B are prime, and the three
// equalities do not constrain the parts any further, so a composite part
// satisfies the relation as readily as a prime one.
//
// "No small factor" is therefore not a property of this proof on its own. It is
// provided by the surrounding checks, and those are the ones that must not be
// weakened:
//   - crypto/modproof (ProofMod) — rules out prime powers and any third factor.
//     Its strength comes from the K=80 iterations; K is a security parameter,
//     not a performance knob.
//   - crypto/paillier (paillier.Proof) — trial division up to
//     verifyPrimesUntil, which covers factors below that bound but not above it.
//
// The former `rangeParameter` constant (and an unused `one`) were dead code
// (never referenced by Verify) and have been removed (SRC-2026-926 part B).
//
// Historical note: this comment previously stated that the range check "forces
// both prime factors to be > ~2⁵¹²". That overstates it — the check constrains
// the shape of the declared factorisation, not the primality of its parts.

// NewProof implements prooffac
func NewProof(Session []byte, ec elliptic.Curve, N0, NCap, s, t, N0p, N0q *big.Int, rand io.Reader) (*ProofFac, error) {
	if ec == nil || N0 == nil || NCap == nil || s == nil || t == nil || N0p == nil || N0q == nil {
		return nil, errors.New("ProveFac constructor received nil value(s)")
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	qNCap := new(big.Int).Mul(q, NCap)
	qN0NCap := new(big.Int).Mul(qNCap, N0)
	q3NCap := new(big.Int).Mul(q3, NCap)
	q3N0NCap := new(big.Int).Mul(q3NCap, N0)
	sqrtN0 := new(big.Int).Sqrt(N0)
	q3SqrtN0 := new(big.Int).Mul(q3, sqrtN0)

	// Fig 28.1 sample
	alpha := common.GetRandomPositiveInt(rand, q3SqrtN0)
	beta := common.GetRandomPositiveInt(rand, q3SqrtN0)
	mu := common.GetRandomPositiveInt(rand, qNCap)
	nu := common.GetRandomPositiveInt(rand, qNCap)
	sigma := common.GetRandomPositiveInt(rand, qN0NCap)
	r := common.GetRandomPositiveRelativelyPrimeInt(rand, q3N0NCap)
	x := common.GetRandomPositiveInt(rand, q3NCap)
	y := common.GetRandomPositiveInt(rand, q3NCap)

	// Fig 28.1 compute
	modNCap := common.ModInt(NCap)

	var P, Q *big.Int
	if common.IsConstantTimeEnabled() {
		// SECURITY: Use constant-time exponentiation for secret exponents N0p, N0q
		// See: https://github.com/golang/go/issues/20654
		ctModNCap := common.NewCTModInt(NCap)
		P = ctModNCap.ExpCT(s, N0p)
		Q = ctModNCap.ExpCT(s, N0q)
	} else {
		P = modNCap.Exp(s, N0p)
		Q = modNCap.Exp(s, N0q)
	}

	// P = s^N0p * t^mu mod NCap
	P = modNCap.Mul(P, modNCap.Exp(t, mu)) // mu is random, not secret

	// Q = s^N0q * t^nu mod NCap
	Q = modNCap.Mul(Q, modNCap.Exp(t, nu)) // nu is random, not secret

	// A, B, T use random exponents (alpha, beta, x, y, r) - non-secret, regular exp is fine
	A := modNCap.Exp(s, alpha)
	A = modNCap.Mul(A, modNCap.Exp(t, x))

	B := modNCap.Exp(s, beta)
	B = modNCap.Mul(B, modNCap.Exp(t, y))

	T := modNCap.Exp(Q, alpha)
	T = modNCap.Mul(T, modNCap.Exp(t, r))

	// Fig 28.2 e
	var e *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(fsSession(Session), N0, NCap, s, t, P, Q, A, B, T, sigma)
		e = common.ModReduceHash(q, eHash)
	}

	// Fig 28.3
	// z1 = e * N0p + alpha (reveals N0p in the output, but that's part of the protocol)
	z1 := new(big.Int).Mul(e, N0p)
	z1 = new(big.Int).Add(z1, alpha)

	// z2 = e * N0q + beta
	z2 := new(big.Int).Mul(e, N0q)
	z2 = new(big.Int).Add(z2, beta)

	w1 := new(big.Int).Mul(e, mu)
	w1 = new(big.Int).Add(w1, x)

	w2 := new(big.Int).Mul(e, nu)
	w2 = new(big.Int).Add(w2, y)

	v := new(big.Int).Mul(nu, N0p)
	v = new(big.Int).Sub(sigma, v)
	v = new(big.Int).Mul(e, v)
	v = new(big.Int).Add(v, r)

	return &ProofFac{P: P, Q: Q, A: A, B: B, T: T, Sigma: sigma, Z1: z1, Z2: z2, W1: w1, W2: w2, V: v}, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofFac, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofFacBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofFac", ProofFacBytesParts)
	}
	return &ProofFac{
		P:     new(big.Int).SetBytes(bzs[0]),
		Q:     new(big.Int).SetBytes(bzs[1]),
		A:     new(big.Int).SetBytes(bzs[2]),
		B:     new(big.Int).SetBytes(bzs[3]),
		T:     new(big.Int).SetBytes(bzs[4]),
		Sigma: new(big.Int).SetBytes(bzs[5]),
		Z1:    new(big.Int).SetBytes(bzs[6]),
		Z2:    new(big.Int).SetBytes(bzs[7]),
		W1:    new(big.Int).SetBytes(bzs[8]),
		W2:    new(big.Int).SetBytes(bzs[9]),
		V:     new(big.Int).SetBytes(bzs[10]),
	}, nil
}

func (pf *ProofFac) Verify(Session []byte, ec elliptic.Curve, N0, NCap, s, t *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() || ec == nil || N0 == nil || NCap == nil || s == nil || t == nil {
		return false
	}
	// Both N0 (the Paillier modulus being attested) and NCap (the auxiliary
	// safe-prime-product ring used by the proof's commitments) must be valid
	// unknown-order moduli, otherwise modular operations downstream can
	// degenerate or panic.
	if !common.IsUsableUnknownOrderModulus(N0, verifyMinModulusBitLen) {
		return false
	}
	if !common.IsUsableUnknownOrderModulus(NCap, verifyMinModulusBitLen) {
		return false
	}
	// s, t are public generators of QR_{NCap}; require canonical
	// non-trivial unit membership and distinctness.
	if !common.IsCanonicalGenerator(NCap, s) || !common.IsCanonicalGenerator(NCap, t) {
		return false
	}
	if s.Cmp(t) == 0 {
		return false
	}
	// P, Q, A, B, T are prover-supplied commitments in Z_{NCap}* — the
	// equality checks below take them as raw big integers, so without unit
	// membership the prover can submit non-canonical or zero-divisor values
	// that bypass the Σ-relation's binding property.
	for _, v := range []*big.Int{pf.P, pf.Q, pf.A, pf.B, pf.T} {
		if !common.IsNumberInMultiplicativeGroup(NCap, v) {
			return false
		}
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	sqrtN0 := new(big.Int).Sqrt(N0)
	q3SqrtN0 := new(big.Int).Mul(q3, sqrtN0)
	qNCap := new(big.Int).Mul(q, NCap)
	qN0NCap := new(big.Int).Mul(qNCap, N0)
	q3NCap := new(big.Int).Mul(q3, NCap)
	q3N0NCap := new(big.Int).Mul(q3NCap, N0)
	upperW := new(big.Int).Lsh(q3NCap, 1)
	upperV := new(big.Int).Lsh(q3N0NCap, 2)

	// Fig 28. Range Check. Use IsInIntervalPositive (not IsInInterval) so
	// the lower bound is open: the honest prover samples all six values
	// via GetRandomPositiveInt, so b == 0 is never produced by the spec.
	if !common.IsInIntervalPositive(pf.Z1, q3SqrtN0) {
		return false
	}

	if !common.IsInIntervalPositive(pf.Z2, q3SqrtN0) {
		return false
	}
	if !common.IsInIntervalPositive(pf.W1, upperW) {
		return false
	}
	if !common.IsInIntervalPositive(pf.W2, upperW) {
		return false
	}
	if !common.IsInIntervalPositive(pf.Sigma, qN0NCap) {
		return false
	}
	if !common.IsInIntervalPositive(pf.V, upperV) {
		return false
	}

	var e *big.Int
	{
		eHash := common.SHA512_256i_TAGGED(fsSession(Session), N0, NCap, s, t, pf.P, pf.Q, pf.A, pf.B, pf.T, pf.Sigma)
		e = common.ModReduceHash(q, eHash)
	}
	// Reject e == 0 for consistency with the Schnorr verifier. The
	// probability is negligible under Fiat-Shamir, but a zero challenge
	// trivially collapses the Σ relation's binding.
	if e.Sign() == 0 {
		return false
	}

	// Fig 28. Equality Check
	modNCap := common.ModInt(NCap)
	{
		LHS := modNCap.Mul(modNCap.Exp(s, pf.Z1), modNCap.Exp(t, pf.W1))
		RHS := modNCap.Mul(pf.A, modNCap.Exp(pf.P, e))

		if LHS.Cmp(RHS) != 0 {
			return false
		}
	}

	{
		LHS := modNCap.Mul(modNCap.Exp(s, pf.Z2), modNCap.Exp(t, pf.W2))
		RHS := modNCap.Mul(pf.B, modNCap.Exp(pf.Q, e))

		if LHS.Cmp(RHS) != 0 {
			return false
		}
	}

	{
		R := modNCap.Mul(modNCap.Exp(s, N0), modNCap.Exp(t, pf.Sigma))
		LHS := modNCap.Mul(modNCap.Exp(pf.Q, pf.Z1), modNCap.Exp(t, pf.V))
		RHS := modNCap.Mul(pf.T, modNCap.Exp(R, e))

		if LHS.Cmp(RHS) != 0 {
			return false
		}
	}

	return true
}

func (pf *ProofFac) ValidateBasic() bool {
	return pf.P != nil &&
		pf.Q != nil &&
		pf.A != nil &&
		pf.B != nil &&
		pf.T != nil &&
		pf.Sigma != nil &&
		pf.Z1 != nil &&
		pf.Z2 != nil &&
		pf.W1 != nil &&
		pf.W2 != nil &&
		pf.V != nil
}

func (pf *ProofFac) Bytes() [ProofFacBytesParts][]byte {
	return [...][]byte{
		pf.P.Bytes(),
		pf.Q.Bytes(),
		pf.A.Bytes(),
		pf.B.Bytes(),
		pf.T.Bytes(),
		pf.Sigma.Bytes(),
		pf.Z1.Bytes(),
		pf.Z2.Bytes(),
		pf.W1.Bytes(),
		pf.W2.Bytes(),
		pf.V.Bytes(),
	}
}
