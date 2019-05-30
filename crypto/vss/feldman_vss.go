// Feldman VSS, based on Paul Feldman, 1987., A practical scheme for non-interactive verifiable secret sharing.
// In Foundations of Computer Science, 1987., 28th Annual Symposium on. IEEE, 427–43
//

package vss

import (
	"fmt"
	"math/big"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common/math"
)

var (
	ErrNumSharesBelowThreshold   = fmt.Errorf("not enough shares to satisfy the threshold")
)

type (
	// Params represents the parameters used in Shamir secret sharing
	Params struct {
		Threshold int      // threshold
		NumShares int      // total num
	}

	Share struct {
		Threshold int
		Xi        *big.Int // xi
		Share     *big.Int // Sigma i
	}

	PolyGs struct {
		Params
		PolyG [][]*big.Int // v0..vt
	}
)

// Returns a new array of secret shares created by Shamir's Secret Sharing Algorithm,
// requiring a minimum number of shares to recreate, of length shares, from the input secret
//
func Create(threshold int, secret *big.Int, indexes []*big.Int) (*Params, *PolyGs, []*Share, error) {
	if secret == nil || indexes == nil {
		return nil, nil, nil, errors.New("vss secret or indexes == nil")
	}

	num := len(indexes)

	if num < threshold {
		return nil, nil, nil, ErrNumSharesBelowThreshold
	}

	poly := samplePolynomial(threshold, secret)
	poly[0] = secret // becomes sigma * G
	polyGs := make([][]*big.Int, len(poly))

	for i, ai := range poly {
		pointX, pointY := EC.ScalarBaseMult(ai.Bytes())
		polyGs[i] = []*big.Int{pointX, pointY}
	}

	params := Params{Threshold: threshold, NumShares: num}
	pGs    := PolyGs{Params: params, PolyG: polyGs}

	shares := make([]*Share, num)

	for i := 0; i < num; i++ {
		share  := evaluatePolynomial(poly, indexes[i])
		shares[i] = &Share{Threshold: threshold, Xi: indexes[i], Share: share}
	}
	return &params, &pGs, shares, nil
}

func (share *Share) Verify(polyGs *PolyGs) bool {
	if share.Threshold != polyGs.Threshold {
		return false
	}

	vX, vY := polyGs.PolyG[0][0], polyGs.PolyG[0][1]
	t := share.Xi

	for i := 1; i < polyGs.Threshold; i++ {
		X, Y := EC.ScalarMult(polyGs.PolyG[i][0], polyGs.PolyG[i][1], t.Bytes())
		vX, vY = EC.Add(vX, vY, X, Y)
		t = new(big.Int).Mul(t, share.Xi)
		t = new(big.Int).Mod(t, EC.N)
	}

	opX, opY := EC.ScalarBaseMult(share.Share.Bytes())

	if vX.Cmp(opX) == 0 && vY.Cmp(opY) == 0 {
		return true
	} else {
		return false
	}
}

func samplePolynomial(threshold int, secret *big.Int) []*big.Int {
	// secret coef is at [0]
	poly := make([]*big.Int, threshold)
	poly[0] = secret

	for i := 1; i < threshold; i++ {
		ai := math.GetRandomPositiveInt(EC.N)
		poly[i] = ai
	}

	return poly
}

// Evauluates a polynomial with coefficients specified in reverse order:
// evaluatePolynomial([a, b, c, d], x):
// 		returns a + bx + cx^2 + dx^3
//
func evaluatePolynomial(poly []*big.Int, value *big.Int) *big.Int {
	last := len(poly) - 1
	result := big.NewInt(0).Set(poly[last])

	for i := last - 1; i >= 0; i-- {
		result = result.Mul(result, value)
		result = result.Add(result, poly[i])
		result = result.Mod(result, EC.N)
	}

	return result
}
