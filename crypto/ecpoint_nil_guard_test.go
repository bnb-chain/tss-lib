// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"math/big"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// NewECPointNoCurveCheck stores whatever it is given, so a point with nil
// coordinates is something an exported constructor can produce.
func nilCoordPoint() *ECPoint { return NewECPointNoCurveCheck(btcec.S256(), nil, nil) }

func wantPanicContaining(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected a panic mentioning %q", want)
		}
		err, ok := r.(error)
		if !ok {
			t.Fatalf("expected the panic value to be an error, got %T: %v", r, r)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("panicked, but not with the intended attributable error: %v", err)
		}
	}()
	fn()
}

func TestECPointXYAttributeNilRatherThanFaulting(t *testing.T) {
	var nilPoint *ECPoint
	wantPanicContaining(t, "ECPoint.X:", func() { nilPoint.X() })
	wantPanicContaining(t, "ECPoint.Y:", func() { nilPoint.Y() })
	wantPanicContaining(t, "ECPoint.X:", func() { nilCoordPoint().X() })
	wantPanicContaining(t, "ECPoint.Y:", func() { nilCoordPoint().Y() })
}

// IsOnCurve has a bool to answer with, so it must not fault. `curve` is a direct
// field of interface type and is nil-able even on a non-nil point.
func TestECPointIsOnCurveIsNilSafe(t *testing.T) {
	var nilPoint *ECPoint
	if nilPoint.IsOnCurve() {
		t.Fatal("a nil point is not on any curve")
	}
	if (&ECPoint{}).IsOnCurve() {
		t.Fatal("a point with no curve is not on any curve")
	}
	if nilCoordPoint().IsOnCurve() {
		t.Fatal("a point with nil coordinates is not on any curve")
	}
}

// Equals guards the outer pointers; the coordinates reached through them are
// nil-able too. A malformed point equals nothing and must not abort the caller.
func TestECPointEqualsIsNilSafeThroughCoordinates(t *testing.T) {
	if nilCoordPoint().Equals(nilCoordPoint()) {
		t.Fatal("two malformed points must not compare equal")
	}
	good := goodPoint(t)
	if good.Equals(nilCoordPoint()) || nilCoordPoint().Equals(good) {
		t.Fatal("a well-formed point must not equal a malformed one")
	}
}

func TestECPointGobEncodeReturnsErrorForNilPoint(t *testing.T) {
	var nilPoint *ECPoint
	if _, err := nilPoint.GobEncode(); err == nil {
		t.Fatal("expected an error, not a nil error")
	}
}

// Negative controls: the guards must not have disarmed the ordinary behaviour.
func goodPoint(t *testing.T) *ECPoint {
	t.Helper()
	p := ScalarBaseMult(btcec.S256(), big.NewInt(5))
	if p == nil {
		t.Fatal("could not build a well-formed point")
	}
	return p
}

func TestECPointWellFormedBehaviourUnchanged(t *testing.T) {
	p := goodPoint(t)
	if p.X() == nil || p.Y() == nil {
		t.Fatal("X/Y must still return coordinates")
	}
	if !p.IsOnCurve() {
		t.Fatal("a well-formed point must still be on the curve")
	}
	if !p.Equals(goodPoint(t)) {
		t.Fatal("two equal well-formed points must still compare equal")
	}
	if _, err := p.GobEncode(); err != nil {
		t.Fatalf("GobEncode must still succeed for a well-formed point: %v", err)
	}
}
