package crypto

import (
	"bytes"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/tss"
)

// ECPoint convenience helper
type ECPoint struct {
	curve  elliptic.Curve
	coords [2]*big.Int
}

func NewECPoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
	if !isOnCurve(curve, X, Y) {
		return nil, fmt.Errorf("NewECPoint: the given point is not on the elliptic curve")
	}
	return &ECPoint{curve, [2]*big.Int{X, Y}}, nil
}

func NewECPointNoCurveCheck(curve elliptic.Curve, X, Y *big.Int) *ECPoint {
	return &ECPoint{curve, [2]*big.Int{X, Y}}
}

func (p *ECPoint) X() *big.Int {
	return new(big.Int).Set(p.coords[0])
}

func (p *ECPoint) Y() *big.Int {
	return new(big.Int).Set(p.coords[1])
}

func (p *ECPoint) Add(p1 *ECPoint) (*ECPoint, error) {
	x, y := p.curve.Add(p.X(), p.Y(), p1.X(), p1.Y())
	return NewECPoint(p.curve, x, y)
}

func (p *ECPoint) ScalarMult(k *big.Int) *ECPoint {
	x, y := p.curve.ScalarMult(p.X(), p.Y(), k.Bytes())
	newP, _ := NewECPoint(p.curve, x, y) // it must be on the curve, no need to check.
	return newP
}

func (p *ECPoint) IsOnCurve() bool {
	return isOnCurve(p.curve, p.coords[0], p.coords[1])
}

func (p *ECPoint) Equals(p2 *ECPoint) bool {
	if p == nil || p2 == nil {
		return false
	}
	return p.X().Cmp(p2.X()) == 0 && p.Y().Cmp(p2.Y()) == 0
}

func (p *ECPoint) SetCurve(curve elliptic.Curve) *ECPoint {
	p.curve = curve
	return p
}

func (p *ECPoint) ValidateBasic() bool {
	return p != nil && p.coords[0] != nil && p.coords[1] != nil && p.IsOnCurve()
}

func ScalarBaseMult(curve elliptic.Curve, k *big.Int) *ECPoint {
	x, y := curve.ScalarBaseMult(k.Bytes())
	p, _ := NewECPoint(curve, x, y) // it must be on the curve, no need to check.
	return p
}

func isOnCurve(c elliptic.Curve, x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	return c.IsOnCurve(x, y)
}

// ----- //

func FlattenECPoints(in []*ECPoint) ([]*big.Int, error) {
	if in == nil {
		return nil, errors.New("FlattenECPoints encountered a nil in slice")
	}
	flat := make([]*big.Int, 0, len(in)*2)
	for _, point := range in {
		if point == nil || point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("FlattenECPoints found nil point/coordinate")
		}
		flat = append(flat, point.coords[0])
		flat = append(flat, point.coords[1])
	}
	return flat, nil
}

func UnFlattenECPoints(curve elliptic.Curve, in []*big.Int, noCurveCheck ...bool) ([]*ECPoint, error) {
	if in == nil || len(in)%2 != 0 {
		return nil, errors.New("UnFlattenECPoints expected an in len divisible by 2")
	}
	var err error
	unFlat := make([]*ECPoint, len(in)/2)
	for i, j := 0, 0; i < len(in); i, j = i+2, j+1 {
		if len(noCurveCheck) == 0 || noCurveCheck[0] == false {
			unFlat[j], err = NewECPoint(curve, in[i], in[i+1])
			if err != nil {
				return nil, err
			}
		} else {
			unFlat[j] = NewECPointNoCurveCheck(curve, in[i], in[i+1])
		}
	}
	for _, point := range unFlat {
		if point.coords[0] == nil || point.coords[1] == nil {
			return nil, errors.New("UnFlattenECPoints found nil coordinate after unpack")
		}
	}
	return unFlat, nil
}

// ----- //

func (p *ECPoint) GobEncode() ([]byte, error) {
	buf := &bytes.Buffer{}
	x, err := p.coords[0].GobEncode()
	if err != nil {
		return nil, err
	}
	y, err := p.coords[1].GobEncode()
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, uint32(len(x)))
	if err != nil {
		return nil, err
	}
	buf.Write(x)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(y)))
	if err != nil {
		return nil, err
	}
	buf.Write(y)

	return buf.Bytes(), nil
}

func (p *ECPoint) GobDecode(buf []byte) error {
	reader := bytes.NewReader(buf)
	var length uint32
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return err
	}
	x := make([]byte, length)
	n, err := reader.Read(x)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return err
	}
	y := make([]byte, length)
	n, err = reader.Read(y)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}

	X := new(big.Int)
	if err := X.GobDecode(x); err != nil {
		return err
	}
	Y := new(big.Int)
	if err := Y.GobDecode(y); err != nil {
		return err
	}
	p.curve = tss.EC()
	p.coords = [2]*big.Int{X, Y}
	if !p.IsOnCurve() {
		return errors.New("ECPoint.UnmarshalJSON: the point is not on the elliptic curve")
	}
	return nil
}

// ----- //

// crypto.ECPoint is not inherently json marshal-able
func (p *ECPoint) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Coords [2]*big.Int
	}{
		Coords: p.coords,
	})
}

func (p *ECPoint) UnmarshalJSON(payload []byte) error {
	aux := &struct {
		Coords [2]*big.Int
	}{}
	if err := json.Unmarshal(payload, &aux); err != nil {
		return err
	}
	p.curve = tss.EC()
	p.coords = [2]*big.Int{aux.Coords[0], aux.Coords[1]}
	if !p.IsOnCurve() {
		return errors.New("ECPoint.UnmarshalJSON: the point is not on the elliptic curve")
	}
	return nil
}
