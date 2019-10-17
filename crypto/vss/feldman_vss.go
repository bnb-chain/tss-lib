// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Feldman VSS, based on Paul Feldman, 1987., A practical scheme for non-interactive verifiable secret sharing.
// In Foundations of Computer Science, 1987., 28th Annual Symposium on. IEEE, 427–43
//

package vss

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

type (
	Share struct {
		Threshold int
		ID,       // xi
		Share *big.Int // Sigma i
	}

	Vs []*crypto.ECPoint // v0..vt

	Shares []*Share
)

var (
	ErrNumSharesBelowThreshold = fmt.Errorf("not enough shares to satisfy the threshold")

	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

// Returns a new array of secret shares created by Shamir's Secret Sharing Algorithm,
// requiring a minimum number of shares to recreate, of length shares, from the input secret
//
func Create(threshold int, secret *big.Int, indexes []*big.Int) (Vs, Shares, error) {
	if secret == nil || indexes == nil {
		return nil, nil, fmt.Errorf("vss secret or indexes == nil: %v %v", secret, indexes)
	}
	if threshold < 1 {
		return nil, nil, errors.New("vss threshold < 1")
	}
	num := len(indexes)
	if num < threshold {
		return nil, nil, ErrNumSharesBelowThreshold
	}

	poly := samplePolynomial(threshold, secret)
	poly[0] = secret // becomes sigma*G in v
	v := make(Vs, len(poly))
	for i, ai := range poly {
		v[i] = crypto.ScalarBaseMult(tss.EC(), ai)
	}

	shares := make(Shares, num)
	for i := 0; i < num; i++ {
		if indexes[i].Cmp(big.NewInt(0)) == 0 {
			return nil, nil, fmt.Errorf("party index should not be 0")
		}
		share := evaluatePolynomial(threshold, poly, indexes[i])
		shares[i] = &Share{Threshold: threshold, ID: indexes[i], Share: share}
	}
	return v, shares, nil
}

func (share *Share) Verify(threshold int, vs Vs) bool {
	if share.Threshold != threshold || vs == nil {
		return false
	}
	var err error
	modQ := common.ModInt(tss.EC().Params().N)
	v, t := vs[0], one // YRO : we need to have our accumulator outside of the loop
	for j := 1; j <= threshold; j++ {
		// t = k_i^j
		t = modQ.Mul(t, share.ID)
		// v = v * v_j^t
		vjt := vs[j].SetCurve(tss.EC()).ScalarMult(t)
		v, err = v.SetCurve(tss.EC()).Add(vjt)
		if err != nil {
			return false
		}
	}
	sigmaGi := crypto.ScalarBaseMult(tss.EC(), share.Share)
	return sigmaGi.Equals(v)
}

func (shares Shares) ReConstruct() (secret *big.Int, err error) {
	if shares != nil && shares[0].Threshold > len(shares) {
		return nil, ErrNumSharesBelowThreshold
	}
	modN := common.ModInt(tss.EC().Params().N)

	// x coords
	xs := make([]*big.Int, 0)
	for _, share := range shares {
		xs = append(xs, share.ID)
	}

	secret = zero
	for i, share := range shares {
		times := one
		for j := 0; j < len(xs); j++ {
			if j == i {
				continue
			}
			sub := modN.Sub(xs[j], share.ID)
			subInv := modN.ModInverse(sub)
			div := modN.Mul(xs[j], subInv)
			times = modN.Mul(times, div)
		}

		fTimes := modN.Mul(share.Share, times)
		secret = modN.Add(secret, fTimes)
	}

	return secret, nil
}

func samplePolynomial(threshold int, secret *big.Int) []*big.Int {
	q := tss.EC().Params().N
	v := make([]*big.Int, threshold+1)
	v[0] = secret
	for i := 1; i <= threshold; i++ {
		ai := common.GetRandomPositiveInt(q)
		v[i] = ai
	}
	return v
}

// Evauluates a polynomial with coefficients such that:
// evaluatePolynomial([a, b, c, d], x):
// 		returns a + bx + cx^2 + dx^3
//
func evaluatePolynomial(threshold int, v []*big.Int, id *big.Int) (result *big.Int) {
	q := tss.EC().Params().N
	modQ := common.ModInt(q)
	result = new(big.Int).Set(v[0])
	X := big.NewInt(int64(1))
	for i := 1; i <= threshold; i++ {
		ai := v[i]
		X = modQ.Mul(X, id)
		aiXi := new(big.Int).Mul(ai, X)
		result = modQ.Add(result, aiXi)
	}
	return
}
