package crypto

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

// ECPoint convenience helper
type ECPoint struct {
	curve  elliptic.Curve
	coords [2]*big.Int
}

func NewECPoint(curve elliptic.Curve, X, Y *big.Int) *ECPoint {
	return &ECPoint{curve, [2]*big.Int{X, Y}}
}

func (p *ECPoint) X() *big.Int {
	return new(big.Int).Set(p.coords[0])
}

func (p *ECPoint) Y() *big.Int {
	return new(big.Int).Set(p.coords[1])
}

func (p *ECPoint) Add(p1 *ECPoint) *ECPoint {
	x, y := p.curve.Add(p.X(), p.Y(), p1.X(), p1.Y())
	return NewECPoint(p.curve, x, y)
}

func (p *ECPoint) ScalarMult(k *big.Int) *ECPoint {
	x, y := p.curve.ScalarMult(p.X(), p.Y(), k.Bytes())
	return NewECPoint(p.curve, x, y)
}

func (p *ECPoint) IsOnCurve() bool {
	if p.coords[0] == nil || p.coords[1] == nil {
		return false
	}
	return p.curve.IsOnCurve(p.coords[0], p.coords[1])
}

func (p *ECPoint) Equals(p2 *ECPoint) bool {
	if p == nil || p2 == nil {
		return false
	}
	return p.X().Cmp(p2.X()) == 0 && p.Y().Cmp(p2.Y()) == 0
}

func ScalarBaseMult(curve elliptic.Curve, k *big.Int) *ECPoint {
	x, y := curve.ScalarBaseMult(k.Bytes())
	return NewECPoint(curve, x, y)
}

// ----- //

func FlattenECPoints(in []*ECPoint) ([]*big.Int, error) {
	if in == nil {
		return nil, errors.New("FlattenECPoints encountered a nil in slice")
	}
	flat := make([]*big.Int, 0, len(in) * 2)
	for _, point := range in {
		if point == nil || point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("FlattenECPoints found nil point/coordinate")
		}
		flat = append(flat, point.coords[0])
		flat = append(flat, point.coords[1])
	}
	return flat, nil
}

func UnFlattenECPoints(curve elliptic.Curve, in []*big.Int) ([]*ECPoint, error) {
	if in == nil || len(in) % 2 != 0 {
		return nil, errors.New("UnFlattenECPoints expected an in len divisible by 2")
	}
	unFlat := make([]*ECPoint, len(in) / 2)
	for i, j := 0, 0; i < len(in); i, j = i + 2, j + 1 {
		unFlat[j] = NewECPoint(curve, in[i], in[i+1])
	}
	for _, point := range unFlat {
		if point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("UnFlattenECPoints found nil coordinate after unpack")
		}
	}
	return unFlat, nil
}
