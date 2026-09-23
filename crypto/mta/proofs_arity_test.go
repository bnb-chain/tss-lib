// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"math/big"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// tenNonEmptyParts is a well-formed ProofBob serialisation: exactly the arity
// ProofBobFromBytes accepts on its own.
func tenNonEmptyParts() [][]byte {
	bzs := make([][]byte, ProofBobBytesParts)
	for i := range bzs {
		bzs[i] = []byte{1}
	}
	return bzs
}

// ProofBobFromBytes accepts either arity by design, so ProofBobWCFromBytes may
// not rely on it to establish that parts 10 and 11 exist. Ten parts must be
// rejected with an error, not walk off the end of the slice.
func TestProofBobWCFromBytesRejectsProofBobArity(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked instead of returning an error: %v", r)
		}
	}()

	pf, err := ProofBobWCFromBytes(btcec.S256(), tenNonEmptyParts())
	if err == nil {
		t.Fatal("expected an error for a ten-part input")
	}
	if pf != nil {
		t.Fatalf("expected a nil proof alongside the error, got %v", pf)
	}
}

// The plain ProofBob path must keep accepting ten parts, or the fix above would
// pass by tightening the wrong function.
func TestProofBobFromBytesStillAcceptsTenParts(t *testing.T) {
	if _, err := ProofBobFromBytes(tenNonEmptyParts()); err != nil {
		t.Fatalf("ProofBobFromBytes must still accept %d parts: %v", ProofBobBytesParts, err)
	}
}

// ProofBobWC.Bytes reads two parts that only exist on the WC form, via
// pf.ProofBob (an embedded pointer) and pf.U (an ECPoint). Delegating to
// ProofBob.Bytes does not establish either. The type's own ValidateBasic does.
func TestProofBobWCBytesRejectsMalformedReceiver(t *testing.T) {
	cases := map[string]*ProofBobWC{
		"nil receiver":       nil,
		"nil embedded proof": {ProofBob: nil, U: nil},
		"nil U":              {ProofBob: &ProofBob{}, U: nil},
	}
	for name, pf := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("expected a panic")
				}
				err, ok := r.(error)
				if !ok {
					t.Fatalf("expected an error panic value, got %T: %v", r, r)
				}
				if !strings.Contains(err.Error(), "ProofBobWC.Bytes:") {
					t.Fatalf("panicked, but not with the intended attributable error: %v", err)
				}
			}()
			pf.Bytes()
		})
	}
}

func TestProofBobBytesRejectsNilField(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected a panic")
		}
		if err, ok := r.(error); !ok || !strings.Contains(err.Error(), "ProofBob.Bytes:") {
			t.Fatalf("panicked, but not with the intended attributable error: %v", r)
		}
	}()
	(&ProofBob{Z: big.NewInt(1)}).Bytes() // every other field nil
}

// Negative control: a well-formed proof must still serialise, or the guards
// above would pass against a Bytes() that panicked unconditionally.
func TestProofBobBytesStillSerialisesWellFormed(t *testing.T) {
	one := big.NewInt(1)
	pf := &ProofBob{Z: one, ZPrm: one, T: one, V: one, W: one, S: one, S1: one, S2: one, T1: one, T2: one}
	if got := pf.Bytes(); len(got) != ProofBobBytesParts {
		t.Fatalf("got %d parts, want %d", len(got), ProofBobBytesParts)
	}
}
