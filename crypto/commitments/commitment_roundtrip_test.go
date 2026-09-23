// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package commitments

import (
	"math/big"
	"reflect"
	"testing"
)

// TestParseSecretsNilLengthPrefixIsRejected covers the exported-API contract of
// ParseSecrets: it takes a caller-supplied []*big.Int, and a nil element in a
// LENGTH-PREFIX position was dereferenced by `secrets[el].Int64()` without any
// check.
//
// builder.Secrets() only ever writes big.NewInt(len(p)) into a prefix slot, so
// a nil prefix is not producible by the one producer this parser is written
// for: this rejects nothing that was ever legal, it only replaces a panic with
// an error.
func TestParseSecretsNilLengthPrefixIsRejected(t *testing.T) {
	cases := []struct {
		name    string
		secrets []*big.Int
	}{
		{"nil first prefix", []*big.Int{nil, big.NewInt(1)}},
		{"nil second prefix", []*big.Int{big.NewInt(1), big.NewInt(7), nil}},
		{"nil prefix, non-nil tail", []*big.Int{nil, nil, nil}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseSecrets panicked instead of returning an error: %v", r)
				}
			}()
			if _, err := ParseSecrets(tt.secrets); err == nil {
				t.Fatalf("ParseSecrets accepted a nil length prefix")
			}
		})
	}
}

// TestParseSecretsKeepsNilDataElements is the negative control for the guard
// above. A nil element in a DATA position is never dereferenced by the parser,
// and it is reachable from the contract-conforming producer: builder.AddPart
// takes []*big.Int and dlnproof.Proof.Serialize explicitly copes with nil
// members of what it passes to AddPart. Rejecting those would break a caller
// the library itself anticipates, so the guard must stay narrow.
func TestParseSecretsKeepsNilDataElements(t *testing.T) {
	parts, err := ParseSecrets([]*big.Int{big.NewInt(2), nil, big.NewInt(5)})
	if err != nil {
		t.Fatalf("ParseSecrets rejected a nil DATA element: %v", err)
	}
	want := [][]*big.Int{{nil, big.NewInt(5)}}
	if !reflect.DeepEqual(parts, want) {
		t.Fatalf("ParseSecrets(...) = %v, want %v", parts, want)
	}
}

// TestBuilderParserRoundTrip pins the contract between the only producer
// (builder.Secrets) and the only parser (ParseSecrets): every part list the
// builder accepts must come back out of the parser unchanged, including the
// zero-length parts the builder happily encodes.
//
// A zero-length part in the FINAL position used to be dropped silently,
// because the data step advanced `el` by 0 and the loop condition ended the
// pass before the part was appended. Two parts went in, one came out.
func TestBuilderParserRoundTrip(t *testing.T) {
	one, two, three := big.NewInt(1), big.NewInt(2), big.NewInt(3)
	cases := []struct {
		name  string
		parts [][]*big.Int
	}{
		{"single part", [][]*big.Int{{one}}},
		{"max parts", [][]*big.Int{{one}, {one, two}, {one, two, three}}},
		{"single empty part", [][]*big.Int{{}}},
		{"leading empty part", [][]*big.Int{{}, {one}}},
		{"trailing empty part", [][]*big.Int{{one}, {}}},
		{"interior empty part", [][]*big.Int{{one}, {}, {two}}},
		{"three parts, trailing empty", [][]*big.Int{{one}, {two}, {}}},
		{"two empty parts", [][]*big.Int{{}, {}}},
		{"three empty parts", [][]*big.Int{{}, {}, {}}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBuilder()
			for _, p := range tt.parts {
				b = b.AddPart(p)
			}
			secrets, err := b.Secrets()
			if err != nil {
				t.Fatalf("builder.Secrets() rejected a part list it should accept: %v", err)
			}
			got, err := ParseSecrets(secrets)
			if err != nil {
				t.Fatalf("ParseSecrets(%v) = error %v", secrets, err)
			}
			if len(got) != len(tt.parts) {
				t.Fatalf("round trip changed the part count: put in %d, got back %d (%v -> %v)",
					len(tt.parts), len(got), secrets, got)
			}
			if !reflect.DeepEqual(got, tt.parts) {
				t.Fatalf("round trip changed the contents: %v -> %v, want %v", secrets, got, tt.parts)
			}
		})
	}
}

// TestSecretsHasNoEncodingForZeroParts documents the one round trip the codec
// deliberately does NOT support. A builder with no parts encodes to the empty
// list, which carries no length prefix at all and is indistinguishable from
// "nothing was sent"; ParseSecrets rejects it rather than inventing an empty
// commitment. Callers must add at least one part.
func TestSecretsHasNoEncodingForZeroParts(t *testing.T) {
	secrets, err := NewBuilder().Secrets()
	if err != nil {
		t.Fatalf("builder.Secrets() with no parts = error %v", err)
	}
	if len(secrets) != 0 {
		t.Fatalf("builder.Secrets() with no parts = %v, want empty", secrets)
	}
	if _, err := ParseSecrets(secrets); err == nil {
		t.Fatal("ParseSecrets accepted an empty input; the zero-part case is documented as unsupported")
	}
	if _, err := ParseSecrets(nil); err == nil {
		t.Fatal("ParseSecrets accepted nil")
	}
}

// TestParseSecretsRejectsOverCapTrailingEmptyPart pins the one input whose
// verdict this change flips from accept to reject: PartsCap parts followed by a
// trailing zero prefix, i.e. a PartsCap+1'th (empty) part.
//
// It used to be accepted only because the trailing part was dropped before the
// cap was consulted. builder.Secrets() cannot produce it -- that would take
// PartsCap+1 parts, which it rejects outright -- so no contract-conforming
// producer emits this encoding.
func TestParseSecretsRejectsOverCapTrailingEmptyPart(t *testing.T) {
	one := big.NewInt(1)
	zero := big.NewInt(0)
	overCap := []*big.Int{one, one, one, one, one, one, zero} // 3 parts + a 4th, empty
	if _, err := ParseSecrets(overCap); err == nil {
		t.Fatal("ParseSecrets accepted PartsCap+1 parts")
	}

	// Negative control: the same encoding without the extra empty part -- the
	// largest thing builder.Secrets() can emit -- must still be accepted.
	atCap := overCap[:len(overCap)-1]
	parts, err := ParseSecrets(atCap)
	if err != nil {
		t.Fatalf("ParseSecrets rejected exactly PartsCap parts: %v", err)
	}
	if len(parts) != PartsCap {
		t.Fatalf("ParseSecrets(%v) returned %d parts, want %d", atCap, len(parts), PartsCap)
	}
}
