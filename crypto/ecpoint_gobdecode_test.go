// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto

import (
	"encoding/binary"
	"math/big"
	"runtime"
	"strings"
	"testing"

	"github.com/bnb-chain/tss-lib/v4/tss"
)

// gobBlob assembles the wire shape GobEncode produces: a little-endian uint32
// length followed by that many bytes, twice.
func gobBlob(declared uint32, body []byte) []byte {
	buf := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint32(buf, declared)
	return append(buf, body...)
}

// TestGobDecodeDoesNotAllocateOnDeclaredLength pins the allocation bound. The
// declared length is a 4-byte attacker-chosen uint32 that used to reach
// make([]byte, length) with nothing between the read and the allocation: the
// only comparison, n != int(length), ran AFTER the buffer existed. Four bytes
// of input bought a 4 GiB allocation.
func TestGobDecodeDoesNotAllocateOnDeclaredLength(t *testing.T) {
	for _, declared := range []uint32{0xFFFFFFFF, 1 << 30, 1 << 20} {
		blob := gobBlob(declared, nil)

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		err := new(ECPoint).GobDecode(blob)
		runtime.ReadMemStats(&after)

		if err == nil {
			t.Fatalf("GobDecode accepted a %d-byte blob declaring %d bytes", len(blob), declared)
		}
		if !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("GobDecode(declared=%d) rejected for the wrong reason: %v", declared, err)
		}
		// The honest encoding of a secp256k1 point is 74 bytes; a megabyte of
		// headroom is four orders of magnitude short of the 4 GiB the
		// unguarded make() reserved.
		if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
			t.Fatalf("GobDecode allocated %d bytes for a %d-byte input declaring %d",
				grew, len(blob), declared)
		}
	}
}

// TestGobDecodeSecondLengthIsBoundedToo covers the y coordinate: its length
// header is read after x has been consumed, so the bound has to be against
// what is left of the reader at that point, not against the original buffer.
func TestGobDecodeSecondLengthIsBoundedToo(t *testing.T) {
	x, err := big.NewInt(7).GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	blob := append(gobBlob(uint32(len(x)), x), gobBlob(1<<30, nil)...)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err = new(ECPoint).GobDecode(blob)
	runtime.ReadMemStats(&after)

	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("GobDecode did not bound the second length: %v", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("GobDecode allocated %d bytes for a %d-byte input", grew, len(blob))
	}
}

// TestGobDecodeRoundTrip is the negative control: the bound must not touch any
// encoding GobEncode actually produces. It also pins the two shapes that were
// rejected before the bound and must stay rejected for the same reason as
// before -- a truncated body, and a length of zero.
func TestGobDecodeRoundTrip(t *testing.T) {
	for _, k := range []int64{1, 2, 12345, 1 << 40} {
		p := ScalarBaseMult(tss.EC(), big.NewInt(k))
		enc, err := p.GobEncode()
		if err != nil {
			t.Fatalf("GobEncode(%d): %v", k, err)
		}
		dec := new(ECPoint)
		if err := dec.GobDecode(enc); err != nil {
			t.Fatalf("GobDecode of an honest %d-byte encoding failed: %v", len(enc), err)
		}
		if !dec.Equals(p) {
			t.Fatalf("gob round trip changed the point for k=%d", k)
		}
	}

	// Truncated body: declares one byte more than it carries.
	x, err := big.NewInt(7).GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	if err := new(ECPoint).GobDecode(gobBlob(uint32(len(x)+1), x)); err == nil {
		t.Fatal("GobDecode accepted a truncated body")
	}
	// Zero-length coordinate: big.Int.GobEncode never emits an empty encoding,
	// so this stays rejected (by big.Int.GobDecode) rather than by the bound.
	if err := new(ECPoint).GobDecode(gobBlob(0, nil)); err == nil {
		t.Fatal("GobDecode accepted a zero-length coordinate")
	}
}
