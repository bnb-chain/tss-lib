// Copyright © 2019-2024 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Package common provides constant-time big integer operations for cryptographic use.
//
// SECURITY NOTE: Go's math/big package is NOT constant-time and should not be used
// with secret values. This module provides constant-time alternatives using
// filippo.io/bigmod, which is the same library used by Go's crypto/rsa.
//
// Reference: https://github.com/golang/go/issues/20654

package common

import (
	"crypto/rand"
	"crypto/subtle"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/bigmod"
)

// constantTimeEnabled controls whether constant-time operations are used.
// Default is true because private-key operations must not depend on caller
// opt-in for timing side-channel protection.
var constantTimeEnabled int32 = 1

// EnableConstantTimeOps enables constant-time cryptographic operations.
// Call this at application startup if timing side-channel protection is required.
func EnableConstantTimeOps() {
	atomic.StoreInt32(&constantTimeEnabled, 1)
}

// DisableConstantTimeOps disables constant-time operations. This is NOT the
// default: constantTimeEnabled is initialised to 1 above, and has been since
// the commit that flipped it. Call this only to trade side-channel resistance
// for throughput, knowingly.
func DisableConstantTimeOps() {
	atomic.StoreInt32(&constantTimeEnabled, 0)
}

// IsConstantTimeEnabled returns true if constant-time operations are enabled.
func IsConstantTimeEnabled() bool {
	return atomic.LoadInt32(&constantTimeEnabled) == 1
}

// CTModInt provides constant-time modular arithmetic using filippo.io/bigmod.
// This is the recommended implementation as bigmod is:
// 1. Maintained by the Go crypto team lead (Filippo Valsorda)
// 2. The same code used internally by crypto/rsa and crypto/ecdsa
// 3. Highly optimized with architecture-specific assembly
type CTModInt struct {
	mod        *bigmod.Modulus
	modBigInt  *big.Int
	inverseExp []byte // Exponent for modular inverse: p-2 (prime) or phi(n)-1 (composite)
	byteLen    int
	bytePool   sync.Pool
}

// NewCTModInt creates a constant-time modular context using bigmod.
// Note: bigmod requires odd modulus for Exp operations.
func NewCTModInt(mod *big.Int) *CTModInt {
	modBytes := mod.Bytes()
	m, err := bigmod.NewModulus(modBytes)
	if err != nil {
		// Fallback: should not happen for valid modulus
		panic(err)
	}

	// Pre-compute mod-2 for Fermat inverse: a^(-1) = a^(mod-2) mod mod
	modMinusTwo := new(big.Int).Sub(mod, big.NewInt(2))

	byteLen := len(modBytes)
	return &CTModInt{
		mod:        m,
		modBigInt:  new(big.Int).Set(mod),
		inverseExp: modMinusTwo.Bytes(),
		byteLen:    byteLen,
		bytePool: sync.Pool{
			New: func() interface{} {
				return make([]byte, byteLen)
			},
		},
	}
}

// reduceToPaddedBytes reduces val mod ct.modBigInt and returns a zero-padded
// byte slice of length ct.byteLen suitable for bigmod.Nat.SetBytes.
// The reduction uses big.Int.Mod which is safe here because the modulus is public.
func (ct *CTModInt) reduceToPaddedBytes(val *big.Int) []byte {
	reduced := val
	if val.Sign() < 0 || val.Cmp(ct.modBigInt) >= 0 {
		reduced = new(big.Int).Mod(val, ct.modBigInt)
	}

	buf := ct.bytePool.Get().([]byte)
	for i := range buf {
		buf[i] = 0
	}
	b := reduced.Bytes()
	copy(buf[ct.byteLen-len(b):], b)
	return buf
}

// ExpCT performs constant-time modular exponentiation using bigmod.
// IMPORTANT: The modulus must be odd. Negative exponents are not supported and will panic.
func (ct *CTModInt) ExpCT(base, exp *big.Int) *big.Int {
	if exp.Sign() == 0 {
		return big.NewInt(1)
	}
	if exp.Sign() < 0 {
		panic("ExpCT: negative exponents are not supported; use ModInverseCT explicitly")
	}

	paddedBase := ct.reduceToPaddedBytes(base)
	defer func() {
		for i := range paddedBase {
			paddedBase[i] = 0
		}
		ct.bytePool.Put(paddedBase)
	}()

	baseNat := bigmod.NewNat()
	baseNat.SetBytes(paddedBase, ct.mod)

	expBytes := exp.Bytes()
	result := bigmod.NewNat()
	result.Exp(baseNat, expBytes, ct.mod)

	return new(big.Int).SetBytes(result.Bytes(ct.mod))
}

// ModInverseCT computes the modular inverse in constant time using Fermat's little theorem.
// For a prime modulus p: a^(-1) = a^(p-2) mod p
// For a non-prime modulus n with known phi(n): a^(-1) = a^(phi(n)-1) mod n
// SECURITY: This uses constant-time Exp, making the entire operation constant-time.
// Note: The modulus should be prime for this to work correctly. For composite moduli,
// use NewCTModIntWithPhi to provide phi(n).
func (ct *CTModInt) ModInverseCT(a *big.Int) *big.Int {
	if a.Sign() == 0 {
		return nil
	}

	paddedA := ct.reduceToPaddedBytes(a)
	defer func() {
		for i := range paddedA {
			paddedA[i] = 0
		}
		ct.bytePool.Put(paddedA)
	}()

	aNat := bigmod.NewNat()
	aNat.SetBytes(paddedA, ct.mod)

	result := bigmod.NewNat()
	result.Exp(aNat, ct.inverseExp, ct.mod)

	return new(big.Int).SetBytes(result.Bytes(ct.mod))
}

// Mod returns the modulus as a big.Int.
func (ct *CTModInt) Mod() *big.Int {
	return new(big.Int).Set(ct.modBigInt)
}

// MulCT performs constant-time modular multiplication using bigmod.
func (ct *CTModInt) MulCT(x, y *big.Int) *big.Int {
	paddedX := ct.reduceToPaddedBytes(x)
	paddedY := ct.reduceToPaddedBytes(y)
	defer func() {
		for i := range paddedX {
			paddedX[i] = 0
		}
		ct.bytePool.Put(paddedX)
	}()
	defer func() {
		for i := range paddedY {
			paddedY[i] = 0
		}
		ct.bytePool.Put(paddedY)
	}()

	xNat := bigmod.NewNat()
	yNat := bigmod.NewNat()
	xNat.SetBytes(paddedX, ct.mod)
	yNat.SetBytes(paddedY, ct.mod)

	xNat.Mul(yNat, ct.mod)

	return new(big.Int).SetBytes(xNat.Bytes(ct.mod))
}

// NewCTModIntWithPhi creates a constant-time modular context for composite moduli.
// This is required for correct ModInverse on composite moduli where phi(n) is known.
// For RSA-like moduli n = p*q, pass phiN = (p-1)*(q-1).
func NewCTModIntWithPhi(mod, phiN *big.Int) *CTModInt {
	modBytes := mod.Bytes()
	m, err := bigmod.NewModulus(modBytes)
	if err != nil {
		panic(err)
	}

	// For composite modulus: a^(-1) = a^(phi(n)-1) mod n
	phiMinusOne := new(big.Int).Sub(phiN, big.NewInt(1))

	byteLen := len(modBytes)
	return &CTModInt{
		mod:        m,
		modBigInt:  new(big.Int).Set(mod),
		inverseExp: phiMinusOne.Bytes(), // Use phi(n)-1 instead of n-2
		byteLen:    byteLen,
		bytePool: sync.Pool{
			New: func() interface{} {
				return make([]byte, byteLen)
			},
		},
	}
}

// TimingProtection provides response time normalization to prevent timing attacks.
type TimingProtection struct {
	targetDuration time.Duration
	jitterRange    time.Duration
}

// NewTimingProtection creates a TimingProtection with custom parameters.
// targetDuration is the minimum padded duration for every operation.
// jitterRange adds a random delay on top of targetDuration to prevent fingerprinting
// the fixed padding boundary.
func NewTimingProtection(targetDuration, jitterRange time.Duration) *TimingProtection {
	return &TimingProtection{
		targetDuration: targetDuration,
		jitterRange:    jitterRange,
	}
}

// ProtectBigInt wraps a function that returns *big.Int with timing normalization.
// The total execution time is always >= targetDuration + a random jitter, regardless
// of how long the actual operation takes.
func (tp *TimingProtection) ProtectBigInt(fn func() (*big.Int, error)) (*big.Int, error) {
	startTime := time.Now()
	result, err := fn()
	elapsed := time.Since(startTime)

	padTo := tp.targetDuration
	if elapsed > padTo {
		padTo = elapsed
	}
	if tp.jitterRange > 0 {
		jitterNanos, _ := rand.Int(rand.Reader, big.NewInt(int64(tp.jitterRange)))
		padTo += time.Duration(jitterNanos.Int64())
	}
	if remaining := padTo - elapsed; remaining > 0 {
		time.Sleep(remaining)
	}
	return result, err
}

// ConstantTimeCompare compares two big.Int values in constant time.
// Both values are padded to padLen bytes before comparison to avoid leaking
// relative magnitude. If padLen is 0, the maximum of the two byte lengths is used.
func ConstantTimeCompare(a, b *big.Int, padLen int) int {
	aBytes := a.Bytes()
	bBytes := b.Bytes()

	if padLen <= 0 {
		padLen = len(aBytes)
		if len(bBytes) > padLen {
			padLen = len(bBytes)
		}
	}

	padA := make([]byte, padLen)
	padB := make([]byte, padLen)
	if len(aBytes) <= padLen {
		copy(padA[padLen-len(aBytes):], aBytes)
	} else {
		copy(padA, aBytes[len(aBytes)-padLen:])
	}
	if len(bBytes) <= padLen {
		copy(padB[padLen-len(bBytes):], bBytes)
	} else {
		copy(padB, bBytes[len(bBytes)-padLen:])
	}

	return subtle.ConstantTimeCompare(padA, padB)
}
