package mta

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
	testRSAModulusLen     = 2048
)

func TestShareProtocol(t *testing.T) {
	q := tss.EC().Params().N

	sk, pk := paillier.GenerateKeyPair(testPaillierKeyLength)

	a := random.GetRandomPositiveInt(q)
	b := random.GetRandomPositiveInt(q)

	rsaSK, err := rsa.GenerateMultiPrimeKey(rand.Reader, 2, testRSAModulusLen)
	assert.NoError(t, err)
	NTildei, h1i, h2i, err := crypto.GenerateNTildei([2]*big.Int{rsaSK.Primes[0], rsaSK.Primes[1]})
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := crypto.GenerateNTildei([2]*big.Int{rsaSK.Primes[0], rsaSK.Primes[1]})
	assert.NoError(t, err)

	cA, pf, err := AliceInit(pk, a, NTildej, h1j, h2j)
	assert.NoError(t, err)

	_, cB, betaPrm, pfB, err := BobMid(pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j)
	assert.NoError(t, err)

	alpha, err := AliceEnd(pk, pfB, h1i, h2i, cA, cB, NTildei, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))
}

func TestShareProtocolWC(t *testing.T) {
	q := tss.EC().Params().N

	sk, pk := paillier.GenerateKeyPair(testPaillierKeyLength)

	a := random.GetRandomPositiveInt(q)
	b := random.GetRandomPositiveInt(q)

	gBX, gBY := tss.EC().ScalarBaseMult(b.Bytes())
	rsaSK, err := rsa.GenerateMultiPrimeKey(rand.Reader, 2, testRSAModulusLen)
	assert.NoError(t, err)
	NTildei, h1i, h2i, err := crypto.GenerateNTildei([2]*big.Int{rsaSK.Primes[0], rsaSK.Primes[1]})
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := crypto.GenerateNTildei([2]*big.Int{rsaSK.Primes[0], rsaSK.Primes[1]})
	assert.NoError(t, err)

	cA, pf, err := AliceInit(pk, a, NTildej, h1j, h2j)
	assert.NoError(t, err)

	gBPoint := crypto.NewECPoint(tss.EC(), gBX, gBY)
	_, cB, betaPrm, pfB, err := BobMidWC(pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j, gBPoint)
	assert.NoError(t, err)

	alpha, err := AliceEndWC(pk, pfB, gBPoint, cA, cB, NTildei, h1i, h2i, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))
}
