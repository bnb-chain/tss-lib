// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePreParamsTimeout(t *testing.T) {
	start := time.Now()
	preParams, err := GeneratePreParams(5*time.Millisecond, 1)

	assert.Nil(t, preParams)
	assert.NotNil(t, err)
	assert.WithinDuration(t, start, time.Now(), 10*time.Millisecond)
}

func TestGeneratePreParamsWithContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	start := time.Now()
	preParams, err := GeneratePreParamsWithContext(ctx, 1)

	assert.Nil(t, preParams)
	assert.NotNil(t, err)
	assert.WithinDuration(t, start, time.Now(), 10*time.Millisecond)
}

func TestGenerateWithContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	preParams, err := GeneratePreParamsWithContext(ctx, 1)
	assert.NotNil(t, preParams)
	assert.Nil(t, err)
	assert.NotNil(t, preParams.PaillierSK)
	assert.NotNil(t, preParams.NTildei)
	assert.NotNil(t, preParams.H1i)
	assert.NotNil(t, preParams.H2i)
	assert.NotNil(t, preParams.Alpha)
	assert.NotNil(t, preParams.Beta)
	assert.NotNil(t, preParams.P)
	assert.NotNil(t, preParams.Q)
}
