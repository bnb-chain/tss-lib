// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package modproof

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
)

const (
	Iterations         = 80
	ProofModBytesParts = Iterations*2 + 3
	// Minimum modulus bit length accepted by Verify. Matches the keygen/
	// resharing wire-format checks for NTilde (paillierBitsLen = 2048).
	verifyMinModulusBitLen = 2048
	// Maximum modulus bit length accepted by Verify.
	//
	// DERIVATION. sampleYModN below expands the Fiat-Shamir seed in 256-bit
	// blocks -- `blocks := (bitLen + 255) / 256` -- and separates the blocks
	// with a ONE-BYTE tag, `[]byte{byte(j)}`. That tag has 256 distinct values,
	// so the blocks are distinct PRF evaluations only while blocks <= 256; at
	// blocks == 257 the tag wraps and block 256 repeats block 0 byte for byte.
	//   blocks <= 256  <=>  (bitLen + 255) / 256 <= 256  <=>  bitLen <= 65536.
	// Above that the sampler is outside the domain it is written for: the
	// expansion buffer becomes a repetition of an 8 KiB pattern instead of a
	// PRF stream, and Y is no longer the value the derivation claims. Verify
	// declines rather than deriving a Y it cannot justify.
	//
	// The same bound is what caps allocation, which had a floor but no ceiling:
	// N arrives from a caller (via the exported Verify) or off the wire as
	// SetBytes of one protobuf field, and the mask, the expansion buffer and
	// every one of the Iterations candidates are each O(bitLen). A 65537-bit
	// modulus measured 8.2 GiB of allocation and 14s in one Verify call.
	//
	// It excludes nothing this library can produce. keygen and resharing pin a
	// peer's modulus to EXACTLY paillierBitsLen = 2048 before any proof is
	// verified (ecdsa/keygen/round_2.go, ecdsa/resharing/round_4_new_step_2.go),
	// verifyMinModulusBitLen is that same 2048, and this ceiling is 32x it. A
	// caller choosing their own size through paillier.GenerateKeyPair would
	// need a pair of safe primes above 32768 bits to reach it.
	verifyMaxModulusBitLen = 65536
	// Miller-Rabin rounds for the composite check; 30 gives ≤4^-30
	// false-positive rate against arbitrary composites.
	verifyPrimalityRounds = 30
	// fsDomainTag is the per-proof-type Fiat-Shamir domain separator
	// (see facproof.fsSession docstring for rationale).
	fsDomainTag = "tss-lib.v4.modproof"
)

var one = big.NewInt(1)

func fsSession(Session []byte) []byte {
	return append([]byte(fsDomainTag+"|"), Session...)
}

// sampleYModN deterministically derives Y_i ∈ [0, N) by seeding from the
// Fiat-Shamir transcript, expanding via SHA512_256 counter mode to the
// bit length of N, masking down to exactly N.BitLen() bits, and then
// rejecting candidates ≥ N. Rejection probability per attempt is at
// most 1/2 because N ∈ (2^{bitlen−1}, 2^bitlen], so the loop is bounded.
//
// This replaces the earlier `ModReduceHash(N, hash)` derivation, which
// silently produced Y_i in a 256-bit subset of [0, N) when N >> 2^256
// (e.g. for 2048-bit NTilde). The 256-bit support set was enough for
// the soundness error magnitude per iteration but did not match the
// `Y <- Z_N` distribution the paper's formal analysis assumes; the
// expand-then-reject sampler closes that gap. Wire-incompat with v3 by
// design — consumed by the v4 module bump.
//
// Defined for N.BitLen() <= verifyMaxModulusBitLen only: the block tag below
// is a single byte, so past that width the blocks stop being distinct. Verify
// enforces the window; see the constant for the derivation.
func sampleYModN(Session []byte, N *big.Int, transcript []*big.Int) *big.Int {
	seedBig := common.SHA512_256i_TAGGED(fsSession(Session), transcript...)
	// Pad the seed to a fixed 32-byte width so the counter mixing below
	// is canonical regardless of leading-zero bytes in seedBig.Bytes().
	seed := seedBig.Bytes()
	if len(seed) < 32 {
		pad := make([]byte, 32-len(seed))
		seed = append(pad, seed...)
	}
	bitLen := N.BitLen()
	blocks := (bitLen + 255) / 256
	mask := new(big.Int).Lsh(one, uint(bitLen))
	mask.Sub(mask, one)
	counterBz := make([]byte, 4)
	for counter := uint32(0); counter < 1<<31; counter++ {
		binary.BigEndian.PutUint32(counterBz, counter)
		combined := make([]byte, 0, blocks*32)
		for j := 0; j < blocks; j++ {
			block := common.SHA512_256(seed, counterBz, []byte{byte(j)})
			combined = append(combined, block...)
		}
		candidate := new(big.Int).SetBytes(combined)
		candidate.And(candidate, mask)
		if candidate.Cmp(N) < 0 {
			return candidate
		}
	}
	// 1<<31 attempts at rejection rate ≤ 1/2 has failure probability
	// 2^-(2^31), which is far below any cryptographic concern; reaching
	// this point indicates a bug in N's bit-length / mask derivation.
	panic("modproof.sampleYModN: exhausted counter (mask/N invariant violated)")
}

type (
	ProofMod struct {
		W *big.Int
		X [Iterations]*big.Int
		A *big.Int
		B *big.Int
		Z [Iterations]*big.Int
	}
)

// isQuadraticResidue checks Euler criterion
func isQuadraticResidue(X, N *big.Int) bool {
	return big.Jacobi(X, N) == 1
}

func NewProof(Session []byte, N, P, Q *big.Int, rand io.Reader) (*ProofMod, error) {
	Phi := new(big.Int).Mul(new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one))
	// Fig 16.1
	W := common.GetRandomQuadraticNonResidue(rand, N)
	// The verifier has checked the shape of N since it was written; the prover
	// never has. An N with no quadratic non-residue at all — nil, ≤ 1, even, or
	// a perfect square — used to leave the sampler above retrying an acceptance
	// test it cannot pass, and this function is called from keygen round 2 and
	// resharing round 2 with the party mutex held, where not returning means the
	// party is gone for good and its host is told nothing. Fail here instead.
	//
	// This deliberately does not import the rest of Verify's window (the
	// 2048-bit floor, the compositeness test): those reject proofs, not provers,
	// and a caller proving over a modulus of its own choosing is served today.
	if W == nil {
		return nil, fmt.Errorf("modproof: N has no quadratic non-residue to sample; it must be odd, > 1 and not a perfect square")
	}

	// Fig 16.2: Y_i ~ Z_N derived via expand-then-reject sampling so the
	// support set matches the paper's `Y <- Z_N` assumption rather than
	// landing in a 256-bit subset (see sampleYModN docstring).
	Y := [Iterations]*big.Int{}
	for i := range Y {
		Y[i] = sampleYModN(Session, N, append([]*big.Int{W, N}, Y[:i]...))
	}

	// Fig 16.3
	modN := common.ModInt(N)

	var invN *big.Int
	var ctModN *common.CTModInt

	if common.IsConstantTimeEnabled() {
		// N^(-1) mod Phi: Phi is even so bigmod (which requires odd modulus) cannot be used.
		// This is a prover-side computation where we already hold P, Q — timing leakage from
		// ModInverse here doesn't expose secrets to external observers.
		invN = new(big.Int).ModInverse(N, Phi)
		ctModN = common.NewCTModInt(N)
	} else {
		invN = new(big.Int).ModInverse(N, Phi)
	}

	X := [Iterations]*big.Int{}
	// Fix bitLen of A and B
	A := new(big.Int).Lsh(one, Iterations)
	B := new(big.Int).Lsh(one, Iterations)
	Z := [Iterations]*big.Int{}

	// for fourth-root: expo = ((Phi + 4) / 8)^2 mod Phi
	expo := new(big.Int).Add(Phi, big.NewInt(4))
	expo = new(big.Int).Rsh(expo, 3)
	expo = new(big.Int).Mul(expo, expo)
	expo = new(big.Int).Mod(expo, Phi)

	for i := range Y {
		var foundA, foundB int
		var foundXi, foundZi *big.Int
		found := false

		for j := 0; j < 4; j++ {
			a, b := j&1, j&2>>1
			Yi := new(big.Int).SetBytes(Y[i].Bytes())
			if a > 0 {
				Yi = modN.Mul(big.NewInt(-1), Yi)
			}
			if b > 0 {
				Yi = modN.Mul(W, Yi)
			}

			isQRP := isQuadraticResidue(Yi, P)
			isQRQ := isQuadraticResidue(Yi, Q)

			if isQRP && isQRQ {
				var Xi, Zi *big.Int
				if common.IsConstantTimeEnabled() {
					// Use constant-time exponentiation with secret-derived exponents
					Xi = ctModN.ExpCT(Yi, expo)
					Zi = ctModN.ExpCT(Y[i], invN)
				} else {
					Xi = modN.Exp(Yi, expo)
					Zi = modN.Exp(Y[i], invN)
				}

				if !found {
					foundXi, foundZi = Xi, Zi
					foundA, foundB = a, b
					found = true
				}
			}
		}

		if found {
			X[i], Z[i] = foundXi, foundZi
			A.SetBit(A, i, uint(foundA))
			B.SetBit(B, i, uint(foundB))
		}
	}

	pf := &ProofMod{W: W, X: X, A: A, B: B, Z: Z}
	return pf, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofMod, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofModBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofMod", ProofModBytesParts)
	}
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}

	X := [Iterations]*big.Int{}
	copy(X[:], bis[1:(Iterations+1)])

	Z := [Iterations]*big.Int{}
	copy(Z[:], bis[(Iterations+3):])

	return &ProofMod{
		W: bis[0],
		X: X,
		A: bis[Iterations+1],
		B: bis[Iterations+2],
		Z: Z,
	}, nil
}

func (pf *ProofMod) Verify(Session []byte, N *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() {
		return false
	}
	// Validate N before any operation that requires it to be a positive odd
	// composite. big.Jacobi panics on nil/non-positive/even modulus, and
	// RejectionSample loops forever on N <= 1, so the original ordering
	// (which only checked oddness/compositeness at line ~192) left a panic
	// surface reachable from a malformed message.
	//
	// The bit-length window is tested before ProbablyPrime deliberately: that
	// call is 30 modexps over N, so it is itself one of the things an oversized
	// N would buy.
	if N == nil || N.Sign() != 1 || N.Bit(0) == 0 ||
		N.BitLen() < verifyMinModulusBitLen || N.BitLen() > verifyMaxModulusBitLen ||
		N.ProbablyPrime(verifyPrimalityRounds) {
		return false
	}
	// W is range-checked BEFORE isQuadraticResidue, not after. Nothing upstream
	// bounds its size: NewProofFromBytes checks the number of parts, never the
	// size of one, and KGRound2Message2.ValidateBasic does not look at the proof
	// at all. big.Jacobi reduces its argument modulo N first, so its cost grows
	// with the size of W while these comparisons do not, and a W that was never
	// going to be accepted was being reduced before it was measured.
	//
	// The accept set is unchanged: a W outside (0, N) was rejected by this pair
	// of conditions either way. Only the order changed, and with it the cost of
	// saying no -- measured at 38 ms against 2.5 ms for an 8 MB W in
	// TestRejectingAnOutOfRangeWDoesNotDependOnItsSize.
	//
	// How much that is worth depends on how large a message the host lets
	// through, which is not decided in this library.
	if pf.W.Sign() != 1 || pf.W.Cmp(N) != -1 {
		return false
	}
	gcd := new(big.Int).GCD(nil, nil, pf.W, N)
	if gcd.Cmp(one) != 0 {
		return false
	}
	if isQuadraticResidue(pf.W, N) {
		return false
	}
	for i := range pf.Z {
		if pf.Z[i].Sign() != 1 || pf.Z[i].Cmp(N) != -1 {
			return false
		}
		// Honest Z[i] = Y[i]^(N^-1 mod φ) is in Z_N*; rejecting non-units
		// closes the defense-in-depth gap where a malicious prover supplies
		// a non-coprime root that happens to satisfy the modexp identity.
		if new(big.Int).GCD(nil, nil, pf.Z[i], N).Cmp(one) != 0 {
			return false
		}
	}
	for i := range pf.X {
		if pf.X[i].Sign() != 1 || pf.X[i].Cmp(N) != -1 {
			return false
		}
		if new(big.Int).GCD(nil, nil, pf.X[i], N).Cmp(one) != 0 {
			return false
		}
	}
	if pf.A.BitLen() != Iterations+1 {
		return false
	}
	if pf.B.BitLen() != Iterations+1 {
		return false
	}

	modN := common.ModInt(N)
	Y := [Iterations]*big.Int{}
	for i := range Y {
		Y[i] = sampleYModN(Session, N, append([]*big.Int{pf.W, N}, Y[:i]...))
	}

	chs := make(chan bool, Iterations*2)
	for i := 0; i < Iterations; i++ {
		go func(i int) {
			left := modN.Exp(pf.Z[i], N)
			if left.Cmp(Y[i]) != 0 {
				chs <- false
				return
			}
			chs <- true
		}(i)

		go func(i int) {
			a := pf.A.Bit(i)
			b := pf.B.Bit(i)
			if a != 0 && a != 1 {
				chs <- false
				return
			}
			if b != 0 && b != 1 {
				chs <- false
				return
			}
			left := modN.Exp(pf.X[i], big.NewInt(4))
			right := Y[i]
			if a > 0 {
				right = modN.Mul(big.NewInt(-1), right)
			}
			if b > 0 {
				right = modN.Mul(pf.W, right)
			}
			if left.Cmp(right) != 0 {
				chs <- false
				return
			}
			chs <- true
		}(i)
	}

	for i := 0; i < Iterations*2; i++ {
		if !<-chs {
			return false
		}
	}

	return true
}

func (pf *ProofMod) ValidateBasic() bool {
	if pf.W == nil {
		return false
	}
	for i := range pf.X {
		if pf.X[i] == nil {
			return false
		}
	}
	if pf.A == nil {
		return false
	}
	if pf.B == nil {
		return false
	}
	for i := range pf.Z {
		if pf.Z[i] == nil {
			return false
		}
	}
	return true
}

func (pf *ProofMod) Bytes() [ProofModBytesParts][]byte {
	bzs := [ProofModBytesParts][]byte{}
	bzs[0] = pf.W.Bytes()
	for i := range pf.X {
		if pf.X[i] != nil {
			bzs[1+i] = pf.X[i].Bytes()
		}
	}
	bzs[Iterations+1] = pf.A.Bytes()
	bzs[Iterations+2] = pf.B.Bytes()
	for i := range pf.Z {
		if pf.Z[i] != nil {
			bzs[Iterations+3+i] = pf.Z[i].Bytes()
		}
	}
	return bzs
}
