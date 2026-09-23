// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
)

func TestPadToLengthBytesInPlace(t *testing.T) {
	for _, tc := range []struct {
		name   string
		src    []byte
		length int
		want   []byte
	}{
		{"nil src", nil, 3, []byte{0, 0, 0}},
		{"empty src", []byte{}, 3, []byte{0, 0, 0}},
		{"one short", []byte{1, 2}, 3, []byte{0, 1, 2}},
		{"already exact", []byte{1, 2, 3}, 3, []byte{1, 2, 3}},
		{"longer than length", []byte{1, 2, 3, 4}, 3, []byte{1, 2, 3, 4}},
		{"zero length", []byte{1, 2}, 0, []byte{1, 2}},
		{"negative length", []byte{1, 2}, -1, []byte{1, 2}},
		{"nil src, zero length", nil, 0, nil},
	} {
		t.Run(tc.name, func(tt *testing.T) {
			got := common.PadToLengthBytesInPlace(tc.src, tc.length)
			assert.True(tt, bytes.Equal(tc.want, got), "want %v, got %v", tc.want, got)
		})
	}
}

func TestPadToLengthBytesInPlaceLeavesTheCallersSliceAlone(t *testing.T) {
	// Despite the name, this function has never written through to the caller's
	// backing array — `append` reallocates. Fixture code depends on that, so
	// pin it.
	src := []byte{1, 2}
	got := common.PadToLengthBytesInPlace(src, 4)
	assert.Equal(t, []byte{1, 2}, src)
	assert.Equal(t, []byte{0, 0, 1, 2}, got)
}

func TestPadToLengthBytesInPlaceAllocatesOnce(t *testing.T) {
	// The padding used to be prepended one byte at a time, each round
	// reallocating and copying the whole slice: Θ(length²) time and one
	// allocation per padding byte. One allocation of the result, plus copy, is
	// all the job needs.
	src := []byte{0xff, 0xee}
	var sink []byte
	allocs := testing.AllocsPerRun(100, func() {
		sink = common.PadToLengthBytesInPlace(src, 512)
	})
	assert.Len(t, sink, 512)
	assert.LessOrEqual(t, allocs, 2.0, "expected a single allocation, got %v", allocs)
}
