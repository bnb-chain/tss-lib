// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Zero-knowledge proof of knowledge of the discrete logarithm over safe prime product

// A proof of knowledge of the discrete log of an element h2 = hx1 with respect to h1.
// In our protocol, we will run two of these in parallel to prove that two elements h1,h2 generate the same group modN.

package dlnp

import (
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	cmts "github.com/binance-chain/tss-lib/crypto/commitments"
)

const (
	// Two 1024-bit safe primes to produce NTilde
	SafePrimeBitLen = 1024
	Iterations      = 128
)

type (
	Proof struct {
		Alpha,
		T [Iterations]*big.Int
	}
)

func NewProof(h1, h2, x, p, q, N *big.Int) (*Proof, error) {
	if h1.Cmp(N) >= 0 {
		return nil, fmt.Errorf("h1 should less than N")
	}
	if h2.Cmp(N) >= 0 {
		return nil, fmt.Errorf("h2 should less than N")
	}
	modNTildeI := common.ModInt(N)
	h2Verify := modNTildeI.Exp(h1, x)
	if h2Verify.Cmp(h2) != 0 {
		return nil, fmt.Errorf("h2 != x * h1")
	}
	pDoublePlus1 := new(big.Int).Add(new(big.Int).Lsh(p, 1), big.NewInt(1))
	qDoublePlus1 := new(big.Int).Add(new(big.Int).Lsh(q, 1), big.NewInt(1))
	nVerify := new(big.Int).Mul(pDoublePlus1, qDoublePlus1)
	if nVerify.Cmp(N) != 0 {
		return nil, fmt.Errorf("DLN proof failed the chekc (2p+1)(2q+1)=N")
	}

	pMulQ := new(big.Int).Mul(p, q)
	modN, modPQ := common.ModInt(N), common.ModInt(pMulQ)
	a := make([]*big.Int, Iterations)
	alpha := [Iterations]*big.Int{}
	for i := range alpha {
		a[i] = common.GetRandomPositiveInt(pMulQ)
		alpha[i] = modN.Exp(h1, a[i])
	}
	msg := append([]*big.Int{h1, h2, N}, alpha[:]...)
	c := common.SHA512_256i(msg...)
	t := [Iterations]*big.Int{}
	cIBI := new(big.Int)
	for i := range t {
		cI := c.Bit(i)
		cIBI = cIBI.SetInt64(int64(cI))
		t[i] = modPQ.Add(a[i], modPQ.Mul(cIBI, x))
	}
	return &Proof{alpha, t}, nil
}

func (p *Proof) Verify(h1, h2, N *big.Int) bool {
	if p == nil {
		return false
	}
	if h1.Cmp(N) >= 0 {
		return false
	}
	if h2.Cmp(N) >= 0 {
		return false
	}

	if N.BitLen() != SafePrimeBitLen*2 {
		return false
	}
	modN := common.ModInt(N)
	msg := append([]*big.Int{h1, h2, N}, p.Alpha[:]...)
	c := common.SHA512_256i(msg...)
	cIBI := new(big.Int)
	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] == nil || p.T[i] == nil {
			return false
		}
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

func (p *Proof) Marshal() ([][]byte, error) {
	cb := cmts.NewBuilder()
	cb = cb.AddPart(p.Alpha[:]...)
	cb = cb.AddPart(p.T[:]...)
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

func UnmarshalProof(bzs [][]byte) (*Proof, error) {
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}
	parsed, err := cmts.ParseSecrets(bis)
	if err != nil {
		return nil, err
	}
	expParts := 2
	if len(parsed) != expParts {
		return nil, fmt.Errorf("dlnp.UnmarshalProof expected %d parts but got %d", expParts, len(parsed))
	}
	pf := new(Proof)
	if len1 := copy(pf.Alpha[:], parsed[0]); len1 != Iterations {
		return nil, fmt.Errorf("dlnp.UnmarshalProof expected %d but copied %d", Iterations, len1)
	}
	if len2 := copy(pf.T[:], parsed[1]); len2 != Iterations {
		return nil, fmt.Errorf("dlnp.UnmarshalProof expected %d but copied %d", Iterations, len2)
	}
	return pf, nil
}
