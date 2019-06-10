package primes_test

import (
	"testing"

	. "github.com/binance-chain/tss-lib/common/primes"
)

func BenchmarkUntil(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Globally.Clear()
		for n := 1234; n < 1240; n++ {
			Until(int64(n))
		}
	}
}

func BenchmarkGlobally(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Globally.Clear()
		for n := 1234; n < 1240; n++ {
			Globally.Until(int64(n))
		}
	}
}

func BenchmarkFactorize(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Globally.Clear()
		for n := 1234; n < 1240; n++ {
			Factorize(int64(n))
		}
	}
}
