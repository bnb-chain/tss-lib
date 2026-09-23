// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"context"
	"crypto/rand"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_getSafePrime(t *testing.T) {
	prime := new(big.Int).SetInt64(5)
	sPrime := getSafePrime(prime)
	assert.True(t, sPrime.ProbablyPrime(50))
}

func Test_getSafePrime_Bad(t *testing.T) {
	prime := new(big.Int).SetInt64(12)
	sPrime := getSafePrime(prime)
	assert.False(t, sPrime.ProbablyPrime(50))
}

func Test_Validate(t *testing.T) {
	prime := new(big.Int).SetInt64(5)
	sPrime := getSafePrime(prime)
	sgp := &GermainSafePrime{prime, sPrime}
	assert.True(t, sgp.Validate())
}

func Test_Validate_Bad(t *testing.T) {
	prime := new(big.Int).SetInt64(12)
	sPrime := getSafePrime(prime)
	sgp := &GermainSafePrime{prime, sPrime}
	assert.False(t, sgp.Validate())
}

func TestGetRandomGermainPrimeConcurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	sgps, err := GetRandomSafePrimesConcurrent(ctx, 1024, 2, runtime.NumCPU(), rand.Reader)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(sgps))
	for _, sgp := range sgps {
		assert.NotNil(t, sgp)
		assert.True(t, sgp.Validate())
	}
}

// GetRandomSafePrimesConcurrent returns as soon as it has numPrimes results,
// cancels its generators and then waits for them. The generators send on a
// bounded channel with a plain send, so one that is mid-send when the reader
// goes away blocks there forever and takes the deferred waitGroup.Wait() with
// it — the caller never returns and cannot be cancelled.
//
// The window is invisible at 1024 bits, where each prime costs seconds and the
// generator sees the cancellation long before it can fill the buffer. At 6
// bits, where the only candidate is 59, the generator refills the buffer in
// microseconds and wins that race routinely.
// GetRandomSafePrimesConcurrent returns as soon as it has numPrimes results,
// cancels its generators and then waits for them. The generators send on a
// bounded channel with a plain send, so one that is mid-send when the reader
// goes away parks there forever and takes the deferred waitGroup.Wait() with
// it: the caller never returns, and no context deadline can reach it.
//
// The window is invisible at 1024 bits, where a prime costs seconds and the
// generator sees the cancellation long before it can refill the buffer. At 6
// bits, where 59 is the only safe prime in range, the generator refills in
// microseconds and loses the race about 1% of the time -- measured at 23 of
// 2000 calls, so 2000 rounds here miss a regression with probability ~1e-10
// and cost well under a second when the send is cancellable.
func TestGetRandomSafePrimesConcurrentReturnsWhileItsGeneratorsAreStillProducing(t *testing.T) {
	for i := 0; i < 2000; i++ {
		done := make(chan struct{})
		go func() {
			defer close(done)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sgps, err := GetRandomSafePrimesConcurrent(ctx, 6, 2, 1, rand.Reader)
			if err == nil && len(sgps) != 2 {
				t.Errorf("expected 2 safe primes, got %d", len(sgps))
			}
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			// The goroutine is abandoned rather than joined: it is parked on a
			// channel send that nothing will ever read.
			t.Fatalf("did not return on round %d", i)
		}
	}
}
