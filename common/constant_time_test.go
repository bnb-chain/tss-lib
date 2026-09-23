// Copyright © 2019-2024 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"
)

func TestConstantTimeOpsEnabledByDefault(t *testing.T) {
	if !IsConstantTimeEnabled() {
		t.Fatal("constant-time operations must be enabled by default")
	}
}

// TestExpCTCorrectness verifies that constant-time exponentiation produces
// correct results by comparing with math/big.Exp
func TestExpCTCorrectness(t *testing.T) {
	// Generate test parameters - use odd modulus for bigmod
	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	N := new(big.Int).Mul(p, q)

	ctMod := NewCTModInt(N)

	testCases := []struct {
		name    string
		expBits int
	}{
		{"small_exp", 32},
		{"medium_exp", 256},
		{"large_exp", 1024},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			base, _ := rand.Int(rand.Reader, N)
			exp, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(tc.expBits)))

			ctResult := ctMod.ExpCT(base, exp)
			expectedResult := new(big.Int).Exp(base, exp, N)

			if ctResult.Cmp(expectedResult) != 0 {
				t.Errorf("ExpCT result mismatch for %s: got %v, expected %v", tc.name, ctResult, expectedResult)
			}
		})
	}
}

// TestExpCTEdgeCases tests edge cases for constant-time exponentiation
func TestExpCTEdgeCases(t *testing.T) {
	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	N := new(big.Int).Mul(p, q)
	ctMod := NewCTModInt(N)

	base, _ := rand.Int(rand.Reader, N)

	// Test exp = 0
	result := ctMod.ExpCT(base, big.NewInt(0))
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("ExpCT(base, 0) should be 1, got %v", result)
	}

	// Test exp = 1
	result = ctMod.ExpCT(base, big.NewInt(1))
	expected := new(big.Int).Mod(base, N)
	if result.Cmp(expected) != 0 {
		t.Errorf("ExpCT(base, 1) should be base mod N, got %v, expected %v", result, expected)
	}

	// Test base = 0
	result = ctMod.ExpCT(big.NewInt(0), big.NewInt(5))
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("ExpCT(0, exp) should be 0, got %v", result)
	}

	// Test base = 1
	exp, _ := rand.Int(rand.Reader, big.NewInt(1000))
	result = ctMod.ExpCT(big.NewInt(1), exp)
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("ExpCT(1, exp) should be 1, got %v", result)
	}
}

// TestModInverseCTCorrectness verifies constant-time ModInverse correctness
func TestModInverseCTCorrectness(t *testing.T) {
	p, _ := rand.Prime(rand.Reader, 1024)
	ctMod := NewCTModInt(p)

	for i := 0; i < 10; i++ {
		a, _ := rand.Int(rand.Reader, p)
		if a.Cmp(big.NewInt(0)) == 0 {
			a = big.NewInt(1)
		}

		ctInv := ctMod.ModInverseCT(a)
		stdInv := new(big.Int).ModInverse(a, p)

		if ctInv.Cmp(stdInv) != 0 {
			t.Errorf("ModInverseCT mismatch: got %v, expected %v", ctInv, stdInv)
		}

		product := new(big.Int).Mul(a, ctInv)
		product.Mod(product, p)
		if product.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("Inverse verification failed: a * a^(-1) = %v, expected 1", product)
		}
	}
}

// TestMulCTCorrectness verifies constant-time multiplication correctness
func TestMulCTCorrectness(t *testing.T) {
	p, _ := rand.Prime(rand.Reader, 1024)
	ctMod := NewCTModInt(p)

	for i := 0; i < 10; i++ {
		x, _ := rand.Int(rand.Reader, p)
		y, _ := rand.Int(rand.Reader, p)

		ctResult := ctMod.MulCT(x, y)
		expected := new(big.Int).Mul(x, y)
		expected.Mod(expected, p)

		if ctResult.Cmp(expected) != 0 {
			t.Errorf("MulCT mismatch: got %v, expected %v", ctResult, expected)
		}
	}
}

// TestCTModIntWithPhi verifies ModInverse for composite moduli with known phi
func TestCTModIntWithPhi(t *testing.T) {
	// Generate RSA-like modulus n = p * q
	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	n := new(big.Int).Mul(p, q)

	// phi(n) = (p-1) * (q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phiN := new(big.Int).Mul(pMinus1, qMinus1)

	ctMod := NewCTModIntWithPhi(n, phiN)

	for i := 0; i < 5; i++ {
		// Generate a coprime to n
		a, _ := rand.Int(rand.Reader, n)
		gcd := new(big.Int).GCD(nil, nil, a, n)
		for gcd.Cmp(big.NewInt(1)) != 0 {
			a, _ = rand.Int(rand.Reader, n)
			gcd = new(big.Int).GCD(nil, nil, a, n)
		}

		ctInv := ctMod.ModInverseCT(a)
		stdInv := new(big.Int).ModInverse(a, n)

		if ctInv.Cmp(stdInv) != 0 {
			t.Errorf("ModInverseCT with phi mismatch: got %v, expected %v", ctInv, stdInv)
		}

		// Verify: a * a^(-1) = 1 mod n
		product := new(big.Int).Mul(a, ctInv)
		product.Mod(product, n)
		if product.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("Inverse verification with phi failed: a * a^(-1) = %v, expected 1", product)
		}
	}
}

// TestConstantTimeCompare verifies constant-time comparison
func TestConstantTimeCompare(t *testing.T) {
	a := big.NewInt(12345)
	b := big.NewInt(12345)
	c := big.NewInt(54321)

	// Use explicit padLen to avoid leaking relative magnitude
	if ConstantTimeCompare(a, b, 128) != 1 {
		t.Error("ConstantTimeCompare should return 1 for equal values")
	}

	if ConstantTimeCompare(a, c, 128) != 0 {
		t.Error("ConstantTimeCompare should return 0 for different values")
	}

	large := new(big.Int).Lsh(big.NewInt(1), 1024)
	small := big.NewInt(1)
	if ConstantTimeCompare(large, small, 128) != 0 {
		t.Error("ConstantTimeCompare should return 0 for values with different magnitudes")
	}

	// Test with padLen=0 (fallback to maxLen)
	if ConstantTimeCompare(a, b, 0) != 1 {
		t.Error("ConstantTimeCompare with padLen=0 should return 1 for equal values")
	}
}

// TestTimingProtectionBigInt verifies timing protection for BigInt operations
func TestTimingProtectionBigInt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	tp := NewTimingProtection(50*time.Millisecond, 0)

	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	N := new(big.Int).Mul(p, q)

	base, _ := rand.Int(rand.Reader, N)
	exp, _ := rand.Int(rand.Reader, big.NewInt(1000))

	start := time.Now()
	result, err := tp.ProtectBigInt(func() (*big.Int, error) {
		return new(big.Int).Exp(base, exp, N), nil
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("ProtectBigInt returned error: %v", err)
	}
	if result == nil {
		t.Error("ProtectBigInt returned nil result")
	}

	if elapsed < 20*time.Millisecond {
		t.Errorf("TimingProtection should normalize to ~50ms, got %v", elapsed)
	}
}

// BenchmarkExpCT benchmarks constant-time exponentiation
func BenchmarkExpCT(b *testing.B) {
	p, _ := rand.Prime(rand.Reader, 1024)
	q, _ := rand.Prime(rand.Reader, 1024)
	N := new(big.Int).Mul(p, q)
	ctMod := NewCTModInt(N)

	base, _ := rand.Int(rand.Reader, N)
	exp, _ := rand.Int(rand.Reader, N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctMod.ExpCT(base, exp)
	}
}

// BenchmarkExpStandard benchmarks standard math/big exponentiation for comparison
func BenchmarkExpStandard(b *testing.B) {
	p, _ := rand.Prime(rand.Reader, 1024)
	q, _ := rand.Prime(rand.Reader, 1024)
	N := new(big.Int).Mul(p, q)

	base, _ := rand.Int(rand.Reader, N)
	exp, _ := rand.Int(rand.Reader, N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		new(big.Int).Exp(base, exp, N)
	}
}

// TestExpCTTimingConsistency checks timing consistency
func TestExpCTTimingConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	N := new(big.Int).Mul(p, q)
	ctMod := NewCTModInt(N)

	base, _ := rand.Int(rand.Reader, N)

	expLowHamming := new(big.Int).Lsh(big.NewInt(1), 511)
	expHighHamming := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 512), big.NewInt(1))

	const iterations = 100
	var timesLow, timesHigh []time.Duration

	for i := 0; i < iterations; i++ {
		start := time.Now()
		ctMod.ExpCT(base, expLowHamming)
		timesLow = append(timesLow, time.Since(start))

		start = time.Now()
		ctMod.ExpCT(base, expHighHamming)
		timesHigh = append(timesHigh, time.Since(start))
	}

	var sumLow, sumHigh time.Duration
	for i := 0; i < iterations; i++ {
		sumLow += timesLow[i]
		sumHigh += timesHigh[i]
	}
	meanLow := sumLow / time.Duration(iterations)
	meanHigh := sumHigh / time.Duration(iterations)

	ratio := float64(meanHigh) / float64(meanLow)
	if ratio < 0.5 || ratio > 2.0 {
		t.Logf("Warning: Timing ratio between high and low Hamming weight exponents: %.2f", ratio)
		t.Logf("Low Hamming mean: %v, High Hamming mean: %v", meanLow, meanHigh)
	}
}
