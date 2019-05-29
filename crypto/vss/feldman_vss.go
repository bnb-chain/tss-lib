// Feldman VSS, based on Paul Feldman, 1987., A practical scheme for non-interactive verifiable secret sharing.
// In Foundations of Computer Science, 1987., 28th Annual Symposium on. IEEE, 427–43
//
// Implementation details: The code is using EC Points and Scalars. Each party is given an index from 1,..,n and a secret share scalar
// The index of the party is also the point on the polynomial where we treat this number as u32

package vss

import (
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common/math"
)

var (
	ErrIdsLenNotEqualToNumShares = fmt.Errorf("the length of input ids is not equal to the number of shares")
	ErrNumSharesBelowThreshold   = fmt.Errorf("not enough shares to satisfy the threshold")
)

type (
	// Params represents the parameters used in Shamir secret sharing
	Params struct {
		Threshold int      // threshold
		NumShares int      // total num
	}

	PolyGs struct {
		Params
		PolyG [][]*big.Int // x and y
	}

	Share struct {
		Threshold int
		Id        *big.Int // ID, x coordinate
		Share     *big.Int
	}
)

// Returns a new array of secret shares created by Shamir's Secret Sharing Algorithm,
// requiring a minimum number of shares to recreate, of length shares, from the input secret
//
func Create(threshold, num int, indexes []*big.Int, secret *big.Int) (*Params, *PolyGs, []*Share, error) {
	if len(indexes) != num {
		return nil, nil, nil, ErrIdsLenNotEqualToNumShares
	}

	poly := samplePolynomial(threshold, secret)

	// commitments
	polyGs := make([][]*big.Int, len(poly))
	coef0X, coef0Y := EC.ScalarBaseMult(secret.Bytes())
	polyGs[0] = []*big.Int{coef0X, coef0Y}

	for i := range polyGs {
		if i == 0 {  // coef0 is secret
			continue
		}
		pointX, pointY := EC.ScalarBaseMult(poly[i].Bytes())
		polyGs[i] = []*big.Int{pointX, pointY}
	}

	params := Params{Threshold: threshold, NumShares: num}
	pg := PolyGs{Params: params, PolyG: polyGs}

	shares := make([]*Share, num)

	for i := 0; i < num; i++ {
		share  := evaluatePolynomial(poly, indexes[i])
		shareS := &Share{Threshold: threshold, Id: indexes[i], Share: share}
		shares[i] = shareS
	}

	return &params, &pg, shares, nil
}

func (share *Share) Verify(polyGs *PolyGs) bool {
	if share.Threshold != polyGs.Threshold {
		return false
	}
	id := share.Id

	tmpPointX, tmpPointY := polyGs.PolyG[0][0], polyGs.PolyG[0][1]

	for i := 1; i < polyGs.Threshold; i++ {
		pointX, pointY := EC.ScalarMult(polyGs.PolyG[i][0], polyGs.PolyG[i][1], id.Bytes())

		tmpPointX, tmpPointY = EC.Add(tmpPointX, tmpPointY, pointX, pointY)
		id = new(big.Int).Mul(id, share.Id)
		id = new(big.Int).Mod(id, EC.N)
	}

	originalPointX, originalPointY := EC.ScalarBaseMult(share.Share.Bytes())

	if tmpPointX.Cmp(originalPointX) == 0 && tmpPointY.Cmp(originalPointY) == 0 {
		return true
	} else {
		return false
	}
}

func Combine(shares []*Share) (*big.Int, error) {
	if shares != nil && shares[0].Threshold > len(shares) {
		return nil, ErrNumSharesBelowThreshold
	}

	// x coords
	xs := make([]*big.Int, 0)
	for _, share := range shares {
		xs = append(xs, share.Id)
	}

	secret := big.NewInt(0)

	for i, share := range shares {
		times := big.NewInt(1)

		for j := 0; j < len(xs); j++ {
			if j != i {
				sub := new(big.Int).Sub(xs[j], share.Id)
				subInv := new(big.Int).ModInverse(sub, EC.N)
				div  := new(big.Int).Mul(xs[j], subInv)
				times = new(big.Int).Mul(times, div)
				times = new(big.Int).Mod(times, EC.N)
			}
		}

		// sum of f(x) * times()
		fTimes := new(big.Int).Mul(share.Share, times)
		secret  = new(big.Int).Add(secret, fTimes)
		secret  = new(big.Int).Mod(secret, EC.N)
	}

	return secret, nil
}

func samplePolynomial(threshold int, coef0 *big.Int) []*big.Int {
	// secret coef is at [0]
	poly := make([]*big.Int, threshold)
	poly[0] = coef0

	for i := 1; i < threshold; i++ {
		rnd := math.GetRandomPositiveInt(EC.N)
		poly[i] = rnd
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
