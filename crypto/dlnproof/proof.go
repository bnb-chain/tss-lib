// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Zero-knowledge proof of knowledge of the discrete logarithm over safe prime product

// A proof of knowledge of the discrete log of an element h2 = hx1 with respect to h1.
// In our protocol, we will run two of these in parallel to prove that two elements h1,h2 generate the same group modN.

package dlnproof

import (
	"fmt"
	"io"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
	cmts "github.com/bnb-chain/tss-lib/v4/crypto/commitments"
)

const (
	Iterations = 128
	// verifyMinModulusBitLen matches the keygen NTilde bit length so the
	// verifier rejects undersized moduli before running modular operations.
	verifyMinModulusBitLen = 2048
	// fsDomainTag is the per-proof-type Fiat-Shamir domain separator
	// (see facproof.fsSession docstring for rationale).
	fsDomainTag = "tss-lib.v4.dlnproof"
)

func fsSession(Session []byte) []byte {
	return append([]byte(fsDomainTag+"|"), Session...)
}

type (
	Proof struct {
		Alpha,
		T [Iterations]*big.Int
	}
)

var one = big.NewInt(1)

func NewDLNProof(Session []byte, h1, h2, x, p, q, N *big.Int, rand io.Reader) *Proof {
	pMulQ := new(big.Int).Mul(p, q)
	modN, modPQ := common.ModInt(N), common.ModInt(pMulQ)
	a := make([]*big.Int, Iterations)
	alpha := [Iterations]*big.Int{}

	if common.IsConstantTimeEnabled() {
		// SECURITY: Use constant-time exponentiation
		ctModN := common.NewCTModInt(N)
		for i := range alpha {
			a[i] = common.GetRandomPositiveInt(rand, pMulQ)
			alpha[i] = ctModN.ExpCT(h1, a[i])
		}
	} else {
		for i := range alpha {
			a[i] = common.GetRandomPositiveInt(rand, pMulQ)
			alpha[i] = modN.Exp(h1, a[i])
		}
	}

	msg := append([]*big.Int{h1, h2, N}, alpha[:]...)
	c := common.SHA512_256i_TAGGED(fsSession(Session), msg...)
	t := [Iterations]*big.Int{}
	cIBI := new(big.Int)

	if common.IsConstantTimeEnabled() {
		// SECURITY: Use constant-time multiplication for secret x
		ctModPQ := common.NewCTModInt(pMulQ)
		for i := range t {
			cI := c.Bit(i)
			cIBI = cIBI.SetInt64(int64(cI))
			cMulX := ctModPQ.MulCT(cIBI, x)
			t[i] = modPQ.Add(a[i], cMulX)
		}
	} else {
		for i := range t {
			cI := c.Bit(i)
			cIBI = cIBI.SetInt64(int64(cI))
			t[i] = modPQ.Add(a[i], modPQ.Mul(cIBI, x))
		}
	}
	return &Proof{alpha, t}
}

func (p *Proof) Verify(Session []byte, h1, h2, N *big.Int) bool {
	if p == nil {
		return false
	}
	// N must be a plausible safe-prime-product NTilde before any modular op.
	if !common.IsUsableUnknownOrderModulus(N, verifyMinModulusBitLen) {
		return false
	}
	modN := common.ModInt(N)
	// h1, h2 must be canonical generator-shaped elements (1 < h < N and a
	// unit). The earlier code allowed non-canonical h ≡ h' mod N inputs;
	// require the raw bytes to already be in canonical range so any consumer
	// that hashes the wire bytes outside Verify sees the same value.
	if !common.IsCanonicalGenerator(N, h1) || !common.IsCanonicalGenerator(N, h2) {
		return false
	}
	if h1.Cmp(h2) == 0 {
		return false
	}
	for i := range p.T {
		if p.T[i] == nil || p.T[i].Cmp(one) != 1 || p.T[i].Cmp(N) != -1 {
			return false
		}
	}
	for i := range p.Alpha {
		// Alpha[i] = h1^a[i] mod N is also in Z_N* and != 1 for honest
		// provers; same canonical-generator shape applies.
		if !common.IsCanonicalGenerator(N, p.Alpha[i]) {
			return false
		}
	}
	msg := append([]*big.Int{h1, h2, N}, p.Alpha[:]...)
	c := common.SHA512_256i_TAGGED(fsSession(Session), msg...)
	cIBI := new(big.Int)
	for i := 0; i < Iterations; i++ {
		cI := c.Bit(i)
		cIBI = cIBI.SetInt64(int64(cI))
		h1ExpTi := modN.Exp(h1, p.T[i])
		h2ExpCi := modN.Exp(h2, cIBI)
		alphaIMulH2ExpCi := modN.Mul(p.Alpha[i], h2ExpCi)
		if h1ExpTi.Cmp(alphaIMulH2ExpCi) != 0 {
			return false
		}
	}
	return true
}

func (p *Proof) Serialize() ([][]byte, error) {
	cb := cmts.NewBuilder()
	cb = cb.AddPart(p.Alpha[:])
	cb = cb.AddPart(p.T[:])
	ints, err := cb.Secrets()
	if err != nil {
		return nil, err
	}
	bzs := make([][]byte, len(ints))
	for i, part := range ints {
		if part == nil {
			bzs[i] = []byte{}
			continue
		}
		bzs[i] = part.Bytes()
	}
	return bzs, nil
}

func UnmarshalDLNProof(bzs [][]byte) (*Proof, error) {
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}
	parsed, err := cmts.ParseSecrets(bis)
	if err != nil {
		return nil, err
	}
	if len(parsed) != 2 {
		return nil, fmt.Errorf("UnmarshalDLNProof expected %d parts but got %d", 2, len(parsed))
	}
	pf := new(Proof)
	if len1 := copy(pf.Alpha[:], parsed[0]); len1 != Iterations {
		return nil, fmt.Errorf("UnmarshalDLNProof expected %d but copied %d", Iterations, len1)
	}
	if len2 := copy(pf.T[:], parsed[1]); len2 != Iterations {
		return nil, fmt.Errorf("UnmarshalDLNProof expected %d but copied %d", Iterations, len2)
	}
	return pf, nil
}
