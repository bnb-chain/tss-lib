package primes_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/binance-chain/tss-lib/common/primes"
)

func TestUntil(t *testing.T) {
	exp := []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97}
	p := Until(100)
	assert.IsType(t, (*Primes)(nil), p)
	assert.Equal(t, exp, p.List())
}

func TestGlobally_Until(t *testing.T) {
	exp := []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97}
	p := Globally.Until(100)
	assert.IsType(t, (*Primes)(nil), p)
	assert.Equal(t, exp, p.List())
}

func TestFactorize(t *testing.T) {
	exp1 := []int64{2, 2, 5, 5}
	exp2 := []int64{2, 2, 2, 5, 5, 5}
	exp3 := []int64{2, 2, 2, 2, 3, 3}
	f := Factorize(100)
	assert.IsType(t, (*Factors)(nil), f)
	assert.Equal(t, exp1, f.All())
	f = Factorize(1000)
	assert.Equal(t, exp2, f.All())
	f = Factorize(144)
	assert.Equal(t, exp3, f.All())
}

func TestParseFractionString(t *testing.T) {
	fr, err := ParseFractionString("144/1024")
	assert.NoError(t, err)
	assert.IsType(t, (*Fraction)(nil), fr)
}

func TestFraction_Reduce(t *testing.T) {
	fr, err := ParseFractionString("10/100")
	assert.NoError(t, err)
	assert.Equal(t, "1/10", fr.Reduce(-1).String())

	fr, _ = ParseFractionString("144/360")

	assert.Equal(t, "2/5", fr.Reduce(-1).String())
	assert.Equal(t, "144/360", fr.Reduce(0).String())
	assert.Equal(t, "72/180", fr.Reduce(1).String())
	assert.Equal(t, "36/90", fr.Reduce(2).String())
	assert.Equal(t, "18/45", fr.Reduce(3).String())
	assert.Equal(t, "6/15", fr.Reduce(4).String())
	assert.Equal(t, "2/5", fr.Reduce(5).String())
}
