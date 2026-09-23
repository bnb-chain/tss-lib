// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto/paillier"
)

const (
	RangeProofAliceBytesParts = 6
	// verifyMinModulusBitLen matches the keygen wire-format check for
	// Paillier N and NTilde (paillierBitsLen = 2048).
	verifyMinModulusBitLen = 2048
	// fsDomainTag* are per-proof-type Fiat-Shamir domain separators
	// (see facproof.fsSession docstring for rationale).
	fsDomainTagRangeAlice = "tss-lib.v4.mta.range-alice"
	fsDomainTagBob        = "tss-lib.v4.mta.bob"
	fsDomainTagBobWC      = "tss-lib.v4.mta.bob-wc"
)

func fsSessionRangeAlice(Session []byte) []byte {
	return append([]byte(fsDomainTagRangeAlice+"|"), Session...)
}

func fsSessionBob(Session []byte) []byte {
	return append([]byte(fsDomainTagBob+"|"), Session...)
}

func fsSessionBobWC(Session []byte) []byte {
	return append([]byte(fsDomainTagBobWC+"|"), Session...)
}

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

type (
	RangeProofAlice struct {
		Z, U, W, S, S1, S2 *big.Int
	}
)

// counterpartyRingUsable applies, to the ring a prover is about to commit into,
// the shape conditions that RangeProofAlice.Verify and ProofBobWC.Verify both
// apply to it. The ring is the counterparty's keygen output, so this runs BEFORE
// a secret is committed into it rather than after the counterparty has rejected
// the result.
func counterpartyRingUsable(NTilde, h1, h2 *big.Int) bool {
	if NTilde == nil || h1 == nil || h2 == nil {
		return false
	}
	if !common.IsUsableUnknownOrderModulus(NTilde, verifyMinModulusBitLen) {
		return false
	}
	return common.IsCanonicalGenerator(NTilde, h1) &&
		common.IsCanonicalGenerator(NTilde, h2) &&
		h1.Cmp(h2) != 0
}

// ringSideValuesUsable applies, to values this party has just computed IN the
// counterparty's ring, the conditions a verifier applies to them.
//
// ONLY ring-side values belong here. Every other condition a verifier applies is
// a function of this party's own Paillier key or its own randomness, and a
// rejection caused by one of those really is this party's own fault -- which the
// existing attribution already reports correctly. That asymmetry is what makes
// the predicate safe to be incomplete: omitting a ring-decided case costs
// nothing beyond the status quo, while admitting a case that is NOT ring-decided
// would name an innocent counterparty.
//
// The v == 1 condition is applied to every value, uniformly. That is stricter
// than the verifiers, which test it for RangeProofAlice's Z alone. The extra
// strictness is deliberate and costs nothing: a ring-side value of 1 is a
// commitment that binds nothing, and against a ring whose generators have large
// order it occurs with probability about 2^-2046, so no conforming counterparty
// loses a proof to it.
func ringSideValuesUsable(NTilde *big.Int, values ...*big.Int) bool {
	for _, v := range values {
		if v == nil || !common.IsInIntervalPositive(v, NTilde) {
			return false
		}
		if v.Cmp(one) == 0 {
			return false
		}
		if new(big.Int).GCD(nil, nil, v, NTilde).Cmp(one) != 0 {
			return false
		}
	}
	return true
}

// ProveRangeAlice implements Alice's range proof used in the MtA and MtAwc protocols from GG18Spec (9) Fig. 9.
func ProveRangeAlice(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, c, NTilde, h1, h2, m, r *big.Int, rand io.Reader) (*RangeProofAlice, error) {
	if pk == nil || NTilde == nil || h1 == nil || h2 == nil || c == nil || m == nil || r == nil {
		return nil, errors.New("ProveRangeAlice constructor received nil value(s)")
	}
	// (NTilde, h1, h2) is the counterparty's, and so is the verifier that will
	// judge the result. See ErrCounterpartyRingUnusable.
	if !counterpartyRingUsable(NTilde, h1, h2) {
		return nil, ErrCounterpartyRingUnusable
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	qNTilde := new(big.Int).Mul(q, NTilde)
	q3NTilde := new(big.Int).Mul(q3, NTilde)

	// 1.
	alpha := common.GetRandomPositiveInt(rand, q3)
	// 2.
	beta := common.GetRandomPositiveRelativelyPrimeInt(rand, pk.N)

	// 3.
	gamma := common.GetRandomPositiveInt(rand, q3NTilde)

	// 4.
	rho := common.GetRandomPositiveInt(rand, qNTilde)

	// 5.
	modNTilde := common.ModInt(NTilde)
	var z *big.Int
	if common.IsConstantTimeEnabled() {
		// SECURITY: Use constant-time exponentiation for secret message m
		// See: https://github.com/golang/go/issues/20654
		ctModNTilde := common.NewCTModInt(NTilde)
		z = ctModNTilde.ExpCT(h1, m)
	} else {
		z = modNTilde.Exp(h1, m)
	}
	z = modNTilde.Mul(z, modNTilde.Exp(h2, rho)) // rho is random, not secret

	// 6.
	modNSquared := common.ModInt(pk.NSquare())
	u := modNSquared.Exp(pk.Gamma(), alpha)
	u = modNSquared.Mul(u, modNSquared.Exp(beta, pk.N))

	// 7.
	w := modNTilde.Exp(h1, alpha)
	w = modNTilde.Mul(w, modNTilde.Exp(h2, gamma))

	// 8-9. e'
	var e *big.Int
	{ // must use RejectionSample
		eHash := common.SHA512_256i_TAGGED(fsSessionRangeAlice(Session), append(pk.AsInts(), NTilde, h1, h2, c, z, u, w)...)
		e = common.ModReduceHash(q, eHash)
	}

	modN := common.ModInt(pk.N)
	s := modN.Exp(r, e)
	s = modN.Mul(s, beta)

	// s1 = e * m + alpha
	s1 := new(big.Int).Mul(e, m)
	s1 = new(big.Int).Add(s1, alpha)

	// s2 = e * rho + gamma
	s2 := new(big.Int).Mul(e, rho)
	s2 = new(big.Int).Add(s2, gamma)

	pf := &RangeProofAlice{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
	// Do not hand out a proof whose ring-side values the counterparty's own
	// verifier rejects. Z is the one it names explicitly (Verify's
	// `pf.Z.Cmp(one) == 0`), and Z is a function of the counterparty's
	// generators, so without this the counterparty both causes the rejection and
	// reports it against the party that computed the proof.
	if !ringSideValuesUsable(NTilde, pf.Z, pf.W) {
		return nil, ErrCounterpartyRingUnusable
	}
	return pf, nil
}

func RangeProofAliceFromBytes(bzs [][]byte) (*RangeProofAlice, error) {
	if !common.NonEmptyMultiBytes(bzs, RangeProofAliceBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct RangeProofAlice", RangeProofAliceBytesParts)
	}
	return &RangeProofAlice{
		Z:  new(big.Int).SetBytes(bzs[0]),
		U:  new(big.Int).SetBytes(bzs[1]),
		W:  new(big.Int).SetBytes(bzs[2]),
		S:  new(big.Int).SetBytes(bzs[3]),
		S1: new(big.Int).SetBytes(bzs[4]),
		S2: new(big.Int).SetBytes(bzs[5]),
	}, nil
}

func (pf *RangeProofAlice) Verify(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() || ec == nil || pk == nil || pk.N == nil || NTilde == nil || h1 == nil || h2 == nil || c == nil {
		return false
	}
	// pk.N and NTilde must both be plausible unknown-order moduli before any
	// modular arithmetic runs (prevents prime / undersized / even / nil
	// moduli from making downstream operations panic or trivially pass).
	if !common.IsUsableUnknownOrderModulus(pk.N, verifyMinModulusBitLen) {
		return false
	}
	if !common.IsUsableUnknownOrderModulus(NTilde, verifyMinModulusBitLen) {
		return false
	}
	// h1, h2 are public NTilde generators agreed in keygen; require canonical
	// non-trivial unit membership and distinctness.
	if !common.IsCanonicalGenerator(NTilde, h1) || !common.IsCanonicalGenerator(NTilde, h2) || h1.Cmp(h2) == 0 {
		return false
	}
	// c is the Paillier ciphertext from the peer. Require canonical
	// encoding (in (0, N²)) and gcd(c, N) == 1 — the latter prevents
	// c^(-e) mod N² from returning nil when the modular inverse doesn't
	// exist; the former rejects non-canonical c + k·N² that could leak
	// timing differences or bypass downstream invariants.
	if !common.IsCanonicalPaillierCiphertext(c, pk.N) {
		return false
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	upperS2 := new(big.Int).Mul(q3, NTilde)
	upperS2.Lsh(upperS2, 1)

	if !common.IsInIntervalPositive(pf.Z, NTilde) {
		return false
	}
	if !common.IsInIntervalPositive(pf.U, pk.NSquare()) {
		return false
	}
	if !common.IsInIntervalPositive(pf.W, NTilde) {
		return false
	}
	if !common.IsInIntervalPositive(pf.S, pk.N) {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.Z, NTilde).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.U, pk.NSquare()).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.W, NTilde).Cmp(one) != 0 {
		return false
	}
	// Mirror of the ProofBob/WC.Verify gcd(S, N) check. Honest S = r^e ·
	// beta mod N is a unit (beta is sampled coprime to N, r is in Z_N*);
	// reject the non-unit case directly rather than relying on downstream
	// equality checks to catch it.
	if new(big.Int).GCD(nil, nil, pf.S, pk.N).Cmp(one) != 0 {
		return false
	}
	if pf.S1.Cmp(q) == -1 {
		return false
	}
	if pf.S2.Cmp(q) == -1 {
		return false
	}
	if pf.S2.Cmp(upperS2) >= 0 {
		return false
	}
	if pf.S.Cmp(one) == 0 {
		return false
	}
	if pf.Z.Cmp(one) == 0 {
		return false
	}
	if pf.S1.Cmp(pf.S2) == 0 {
		return false
	}

	// 3.
	if pf.S1.Cmp(q3) == 1 {
		return false
	}

	// 1-2. e'
	var e *big.Int
	{ // must use RejectionSample
		eHash := common.SHA512_256i_TAGGED(fsSessionRangeAlice(Session), append(pk.AsInts(), NTilde, h1, h2, c, pf.Z, pf.U, pf.W)...)
		e = common.ModReduceHash(q, eHash)
	}
	// Reject e == 0 for consistency with Schnorr / ProofBobWC. Negligible
	// under Fiat-Shamir but a zero challenge collapses the Σ relation.
	if e.Sign() == 0 {
		return false
	}

	var products *big.Int // for the following conditionals
	minusE := new(big.Int).Sub(zero, e)

	{ // 4. gamma^s_1 * s^N * c^-e
		modNSquared := common.ModInt(pk.NSquare())

		cExpMinusE := modNSquared.Exp(c, minusE)
		sExpN := modNSquared.Exp(pf.S, pk.N)
		gammaExpS1 := modNSquared.Exp(pk.Gamma(), pf.S1)
		// u != (4)
		products = modNSquared.Mul(gammaExpS1, sExpN)
		products = modNSquared.Mul(products, cExpMinusE)
		if pf.U.Cmp(products) != 0 {
			return false
		}
	}

	{ // 5. h_1^s_1 * h_2^s_2 * z^-e
		modNTilde := common.ModInt(NTilde)

		h1ExpS1 := modNTilde.Exp(h1, pf.S1)
		h2ExpS2 := modNTilde.Exp(h2, pf.S2)
		zExpMinusE := modNTilde.Exp(pf.Z, minusE)
		// w != (5)
		products = modNTilde.Mul(h1ExpS1, h2ExpS2)
		products = modNTilde.Mul(products, zExpMinusE)
		if pf.W.Cmp(products) != 0 {
			return false
		}
	}
	return true
}

func (pf *RangeProofAlice) ValidateBasic() bool {
	return pf.Z != nil &&
		pf.U != nil &&
		pf.W != nil &&
		pf.S != nil &&
		pf.S1 != nil &&
		pf.S2 != nil
}

func (pf *RangeProofAlice) Bytes() [RangeProofAliceBytesParts][]byte {
	return [...][]byte{
		pf.Z.Bytes(),
		pf.U.Bytes(),
		pf.W.Bytes(),
		pf.S.Bytes(),
		pf.S1.Bytes(),
		pf.S2.Bytes(),
	}
}
