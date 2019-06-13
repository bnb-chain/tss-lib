package crypto

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

// ECPoint convenience helper
type ECPoint [2]*big.Int

func NewECPoint(X, Y *big.Int) *ECPoint {
	return &ECPoint{X, Y}
}

func (p *ECPoint) X() *big.Int {
	return new(big.Int).Set(p[0])
}

func (p *ECPoint) Y() *big.Int {
	return new(big.Int).Set(p[1])
}

func (p *ECPoint) IsOnCurve(curve elliptic.Curve) bool {
	return curve.IsOnCurve(p[0], p[1])
}

// ----- //

func FlattenECPoints(in []*ECPoint) ([]*big.Int, error) {
	if in == nil {
		return nil, errors.New("FlattenECPoints encountered a nil in slice")
	}
	flat := make([]*big.Int, 0, len(in) * 2)
	for _, point := range in {
		if point == nil || point[0] == nil || point[1] == nil {
			return nil, errors.New("FlattenECPoints found nil point/coordinate")
		}
		flat = append(flat, point[0])
		flat = append(flat, point[1])
	}
	return flat, nil
}

func UnFlattenECPoints(in []*big.Int) ([]*ECPoint, error) {
	if in == nil || len(in) % 2 != 0 {
		return nil, errors.New("UnFlattenECPoints expected an in len divisible by 2")
	}
	unFlat := make([]*ECPoint, len(in) / 2)
	for i, j := 0, 0; i < len(in); i, j = i + 2, j + 1 {
		unFlat[j] = NewECPoint(in[i], in[i + 1])
	}
	for _, point := range unFlat {
		if point[0] == nil || point[1] == nil {
			return nil, errors.New("UnFlattenECPoints found nil coordinate after unpack")
		}
	}
	return unFlat, nil
}

