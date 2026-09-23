// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/edwards/v2"

	"github.com/bnb-chain/tss-lib/v4/tss"
)

// ECPoint convenience helper
type ECPoint struct {
	curve  elliptic.Curve
	coords [2]*big.Int
}

var (
	eight    = big.NewInt(8)
	eightInv = new(big.Int).ModInverse(eight, edwards.Edwards().Params().N)
)

// Creates a new ECPoint and checks that the given coordinates are on the elliptic curve.
func NewECPoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
	if !isOnCurve(curve, X, Y) {
		return nil, fmt.Errorf("NewECPoint: the given point is not on the elliptic curve")
	}
	return &ECPoint{curve, [2]*big.Int{X, Y}}, nil
}

// Creates a new ECPoint without checking that the coordinates are on the elliptic curve.
// Only use this function when you are completely sure that the point is already on the curve.
func NewECPointNoCurveCheck(curve elliptic.Curve, X, Y *big.Int) *ECPoint {
	return &ECPoint{curve, [2]*big.Int{X, Y}}
}

// X and Y return a copy of the respective coordinate.
//
// They panic on a nil receiver or a nil coordinate rather than faulting inside
// (*big.Int).Set. Returning nil instead would not help: every caller in this
// tree immediately calls Cmp or Bytes on the result, so a nil return relocates
// the same fault one frame later and further from its cause. A coordinate can
// legitimately be nil here because NewECPointNoCurveCheck stores whatever it is
// given -- the nil guards that exist are in the CALLERS (Add, ScalarMult,
// Equals), and they guard the outer pointer only.
func (p *ECPoint) X() *big.Int {
	if p == nil || p.coords[0] == nil {
		panic(errors.New("ECPoint.X: nil point or nil X coordinate"))
	}
	return new(big.Int).Set(p.coords[0])
}

func (p *ECPoint) Y() *big.Int {
	if p == nil || p.coords[1] == nil {
		panic(errors.New("ECPoint.Y: nil point or nil Y coordinate"))
	}
	return new(big.Int).Set(p.coords[1])
}

func (p *ECPoint) Add(p1 *ECPoint) (*ECPoint, error) {
	// SECURITY (SRC-2026-641): a nil operand means an upstream
	// ScalarMult/ScalarBaseMult returned nil (identity / off-curve result).
	// Return an error instead of dereferencing nil via X()/Y() so callers can
	// attribute the failure to the responsible peer rather than crashing the
	// process. Every Add call site already checks the returned error.
	if p == nil || p1 == nil {
		return nil, errors.New("ECPoint.Add: nil operand")
	}
	x, y := p.curve.Add(p.X(), p.Y(), p1.X(), p1.Y())
	return NewECPoint(p.curve, x, y)
}

// ScalarMult returns p * k. When k ≡ 0 mod n (identity) or any other input
// produces an off-curve representation, ScalarMult returns nil rather than
// panicking. Callers MUST check the returned pointer before use; pairs of
// hardened call sites (Schnorr / VSS / MtA Verify) validate scalars upstream,
// so a nil return here indicates either an unvalidated direct API consumer
// or a degenerate honest case (zero contribution) that should be treated as
// an error by the protocol.
func (p *ECPoint) ScalarMult(k *big.Int) *ECPoint {
	if p == nil || k == nil {
		return nil
	}
	x, y := p.curve.ScalarMult(p.X(), p.Y(), k.Bytes())
	newP, err := NewECPoint(p.curve, x, y)
	if err != nil {
		return nil
	}
	return newP
}

// ScalarMultErr is the explicit-error variant of ScalarMult. Returns
// (*ECPoint, error) instead of the nil-on-error convention; useful for
// internal callers that want to propagate the curve error.
func (p *ECPoint) ScalarMultErr(k *big.Int) (*ECPoint, error) {
	if p == nil {
		return nil, errors.New("ScalarMultErr: receiver is nil")
	}
	if k == nil {
		return nil, errors.New("ScalarMultErr: scalar k is nil")
	}
	x, y := p.curve.ScalarMult(p.X(), p.Y(), k.Bytes())
	return NewECPoint(p.curve, x, y)
}

func (p *ECPoint) ToECDSAPubKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: p.curve,
		X:     p.X(),
		Y:     p.Y(),
	}
}

// IsOnCurve reports whether the point satisfies its curve equation. A nil point,
// or one with no curve, is not on any curve -- it returns false rather than
// faulting, because it has a bool to say it with. `curve` is a direct field of
// interface type, so it is nil-able even when the point itself is not, and
// isOnCurve dereferences it at c.Params().
func (p *ECPoint) IsOnCurve() bool {
	if p == nil || p.curve == nil {
		return false
	}
	return isOnCurve(p.curve, p.coords[0], p.coords[1])
}

func (p *ECPoint) Curve() elliptic.Curve {
	return p.curve
}

// Equals reports whether the two points have equal coordinates. The nil guard
// covers the OUTER pointers; the coordinates reached through them are nil-able
// too, and X()/Y() now panic on those, so they are tested here as well. A
// malformed point equals nothing, including another malformed point -- a
// comparison has a bool to return and should not abort the caller.
func (p *ECPoint) Equals(p2 *ECPoint) bool {
	if p == nil || p2 == nil {
		return false
	}
	if p.coords[0] == nil || p.coords[1] == nil || p2.coords[0] == nil || p2.coords[1] == nil {
		return false
	}
	return p.X().Cmp(p2.X()) == 0 && p.Y().Cmp(p2.Y()) == 0
}

func (p *ECPoint) SetCurve(curve elliptic.Curve) *ECPoint {
	p.curve = curve
	return p
}

func (p *ECPoint) ValidateBasic() bool {
	return p != nil && p.coords[0] != nil && p.coords[1] != nil && p.IsOnCurve() && !p.IsIdentity()
}

// IsIdentity reports whether p represents the identity element of its
// curve. The two affine representations checked here cover both curve
// families used by tss-lib:
//
//   - Edwards-form curves (Ed25519 via decred/dcrd/dcrec/edwards/v2):
//     the affine identity is (0, 1) and IS on-curve, so it passes the
//     isOnCurve test alone. Without this check, a malicious party can
//     submit (0, 1) as a Schnorr proof's commitment or as a VSS share
//     and the verifier accepts a degenerate proof.
//   - Weierstrass-form curves (secp256k1, NIST): the identity is the
//     point-at-infinity, conventionally (0, 0) in affine form. That
//     coordinate is NOT on-curve and is already rejected by isOnCurve.
//     The (0, 0) branch here is defense-in-depth in case future curve
//     code surfaces a different infinity representation.
//
// Returns false for nil points (no coordinate to inspect).
func (p *ECPoint) IsIdentity() bool {
	if p == nil || p.coords[0] == nil || p.coords[1] == nil {
		return false
	}
	if p.coords[0].Sign() != 0 {
		return false
	}
	return p.coords[1].Sign() == 0 || p.coords[1].Cmp(big.NewInt(1)) == 0
}

// IsInPrimeOrderSubgroup reports whether p lies in the prime-order
// subgroup of its curve, i.e. `[curve.N] * p == identity` where
// `curve.N` is the prime subgroup order.
//
// For prime-order curves (cofactor 1 — secp256k1 / NIST), every on-curve
// point trivially satisfies this by Lagrange's theorem; the explicit
// computation here just confirms it at the cost of one extra ScalarMult.
//
// For composite-cofactor curves (Ed25519, cofactor 8) the check is
// load-bearing: on-curve membership alone admits 8 small-order points
// (the cofactor subgroup) that an adversary can submit as a Schnorr
// commitment, VSS share, etc. to mount small-subgroup attacks. Callers
// in those code paths should use this check (typically via
// ValidateInSubgroup) on every untrusted EC point.
//
// Returns false for nil points or points whose [N]·p does not yield the
// identity element.
func (p *ECPoint) IsInPrimeOrderSubgroup() bool {
	if p == nil || p.coords[0] == nil || p.coords[1] == nil || p.curve == nil {
		return false
	}
	n := p.curve.Params().N
	np := p.ScalarMult(n)
	if np == nil {
		// ScalarMult returns nil when the curve.ScalarMult result is the
		// point-at-infinity (rejected by isOnCurve on Weierstrass). That
		// IS the identity / prime-order witness for those curves.
		return true
	}
	return np.IsIdentity()
}

// ValidateInSubgroup is the stricter sibling of ValidateBasic for
// untrusted EC points on curves with composite cofactor. It runs the
// basic on-curve / non-identity / non-nil checks and additionally
// requires the point to live in the prime-order subgroup. On
// prime-order curves (cofactor 1) the subgroup check is structurally
// guaranteed by IsOnCurve and is skipped to save a ScalarMult.
//
// Callers consuming attacker-controlled EC points (Schnorr Alpha / X /
// V / R, VSS vs[j], MtA ProofBobWC pf.U, etc.) should prefer this over
// ValidateBasic.
func (p *ECPoint) ValidateInSubgroup() bool {
	if !p.ValidateBasic() {
		return false
	}
	if !tss.HasCompositeCofactor(p.curve) {
		return true
	}
	return p.IsInPrimeOrderSubgroup()
}

func (p *ECPoint) EightInvEight() *ECPoint {
	q := p.ScalarMult(eight)
	if q == nil {
		return nil
	}
	return q.ScalarMult(eightInv)
}

// ScalarBaseMult returns g * k (curve base point times k). On any error
// (including k ≡ 0 mod n which yields the off-curve identity) returns nil.
// See ScalarMult doc for the nil-on-error rationale.
func ScalarBaseMult(curve elliptic.Curve, k *big.Int) *ECPoint {
	if curve == nil || k == nil {
		return nil
	}
	x, y := curve.ScalarBaseMult(k.Bytes())
	p, err := NewECPoint(curve, x, y)
	if err != nil {
		return nil
	}
	return p
}

// ScalarBaseMultErr is the explicit-error variant of ScalarBaseMult.
func ScalarBaseMultErr(curve elliptic.Curve, k *big.Int) (*ECPoint, error) {
	if curve == nil {
		return nil, errors.New("ScalarBaseMultErr: curve is nil")
	}
	if k == nil {
		return nil, errors.New("ScalarBaseMultErr: scalar k is nil")
	}
	x, y := curve.ScalarBaseMult(k.Bytes())
	return NewECPoint(curve, x, y)
}

func isOnCurve(c elliptic.Curve, x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	// Reject coordinates outside [0, P) to prevent non-canonical point representations
	// from bypassing the curve equation check via modular reduction (SRC-2026-573).
	P := c.Params().P
	if x.Sign() < 0 || x.Cmp(P) >= 0 || y.Sign() < 0 || y.Cmp(P) >= 0 {
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
		if len(noCurveCheck) == 0 || !noCurveCheck[0] {
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
// Gob helpers for if you choose to encode messages with Gob.

// GobEncode has an error to return, so a nil receiver produces one instead of a
// fault. (A nil coordinate does not need its own case: (*big.Int).GobEncode is
// nil-receiver safe and yields an empty encoding.)
func (p *ECPoint) GobEncode() ([]byte, error) {
	if p == nil {
		return nil, errors.New("ECPoint.GobEncode: nil point")
	}
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

// readLengthPrefixed reads a little-endian uint32 length and then that many
// bytes, refusing to reserve the buffer before the length is known to be
// satisfiable.
//
// The bound comes straight out of GobEncode above, which writes exactly
// 4 + len(x) + 4 + len(y) bytes. Each declared length is therefore at most the
// number of bytes still unread when its prefix is consumed, which is what
// bytes.Reader.Len reports. (The concrete ceiling is much smaller -- a
// coordinate is (*big.Int).GobEncode output, one version/sign byte plus
// ceil(bitLen/8) magnitude bytes, over a field element of tss.EC(), so 33
// bytes and a 74-byte encoding on secp256k1 -- but the remaining-bytes bound
// is exact, needs no curve lookup, and rejects precisely the set the old
// n != int(length) check already rejected.)
//
// That equivalence is the point: bytes.Reader.Read fills min(len(b), remaining)
// in a single call, so any length above the remaining count already failed
// n != int(length). This moves the identical rejection to BEFORE the
// allocation. Previously a 4-byte input declaring 0xFFFFFFFF reserved 4 GiB
// and only then compared the counts.
func readLengthPrefixed(reader *bytes.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return nil, err
	}
	if int64(length) > int64(reader.Len()) {
		return nil, fmt.Errorf("gob decode failed: declared length %d exceeds the %d bytes remaining", length, reader.Len())
	}
	bz := make([]byte, length)
	n, err := reader.Read(bz)
	if n != int(length) || err != nil {
		return nil, fmt.Errorf("gob decode failed: %v", err)
	}
	return bz, nil
}

func (p *ECPoint) GobDecode(buf []byte) error {
	reader := bytes.NewReader(buf)
	x, err := readLengthPrefixed(reader)
	if err != nil {
		return err
	}
	y, err := readLengthPrefixed(reader)
	if err != nil {
		return err
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
	ecName, ok := tss.GetCurveName(p.curve)
	if !ok {
		return nil, fmt.Errorf("cannot find %T name in curve registry, please call tss.RegisterCurve(name, curve) to register it first", p.curve)
	}

	return json.Marshal(&struct {
		Curve  string
		Coords [2]*big.Int
	}{
		Curve:  string(ecName),
		Coords: p.coords,
	})
}

func (p *ECPoint) UnmarshalJSON(payload []byte) error {
	aux := &struct {
		Curve  string
		Coords [2]*big.Int
	}{}
	if err := json.Unmarshal(payload, &aux); err != nil {
		return err
	}
	p.coords = [2]*big.Int{aux.Coords[0], aux.Coords[1]}

	if len(aux.Curve) > 0 {
		ec, ok := tss.GetCurveByName(tss.CurveName(aux.Curve))
		if !ok {
			return fmt.Errorf("cannot find curve named with %s in curve registry, please call tss.RegisterCurve(name, curve) to register it first", aux.Curve)
		}
		p.curve = ec
	} else {
		// forward compatible, use global ec as default value
		p.curve = tss.EC()
	}

	if !p.IsOnCurve() {
		return fmt.Errorf("ECPoint.UnmarshalJSON: the point is not on the elliptic curve (%T) ", p.curve)
	}

	return nil
}
