package mta

import(
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
	testRSAModulusLen = 2048
)

func TestShareProtocol(t *testing.T) {
	q := tss.EC().Params().N

	sk, pk := paillier.GenerateKeyPair(testPaillierKeyLength)

	a := random.GetRandomPositiveInt(q)
	b := random.GetRandomPositiveInt(q)

	rsaPK, err := rsa.GenerateMultiPrimeKey(rand.Reader, 2, testRSAModulusLen)
	NTildei, h1i, h2i, err := keygen.GenerateNTildei(rsaPK.Primes)
	assert.NoError(t, err)

	cA, pf, err := AliceInit(pk, a, NTildei, h1i, h2i)
	assert.NoError(t, err)

	_, cB, _, beta1, err := BobMid(pk, pf, b, cA, nil, nil, nil, nil, nil, nil, NTildei, h1i, h2i)
	assert.NoError(t, err)

	alpha, err := AliceEnd(pk, nil, nil, nil, nil, cB, nil, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + beta1
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, beta1)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))
}
