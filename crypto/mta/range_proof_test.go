package mta

import (
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
	testRSAPrimeBits = 1024
)

func TestProveRangeAlice(t *testing.T) {
	q := tss.EC().Params().N

	sk, pk := paillier.GenerateKeyPair(testPaillierKeyLength)
	m := random.GetRandomPositiveInt(q)

	c, r, err := sk.EncryptAndReturnRandomness(m)
	assert.NoError(t, err)

	primes := [2]*big.Int{random.GetRandomPrimeInt(testRSAPrimeBits), random.GetRandomPrimeInt(testRSAPrimeBits)}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(primes)
	assert.NoError(t, err)
	proof, err := ProveRangeAlice(pk, c, NTildei, h1i, h2i, m, r)
	assert.NoError(t, err)

	ok := proof.Verify(pk, NTildei, h1i, h2i, c)
	assert.True(t, ok, "proof must verify")
}
