package mta

import (
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
	testRSAPrimeBits = 1024
)

func TestProveRangeAlice(t *testing.T) {
	t.Skip("WIP: broken")

	sk, pk := paillier.GenerateKeyPair(testPaillierKeyLength)
	m := random.GetRandomPositiveInt(tss.EC().Params().N)

	c, r, err := sk.EncryptAndReturnRandomness(m)
	assert.NoError(t, err)

	primes := []*big.Int{random.GetRandomPrimeInt(testRSAPrimeBits), random.GetRandomPrimeInt(testRSAPrimeBits)}
	NTildei, h1i, h2i, err := keygen.GenerateNTildei(primes)
	proof := ProveRangeAlice(pk, c, NTildei, h1i, h2i, m, r)
	assert.NoError(t, err)
	t.Log(proof)

	ok := proof.Verify(pk, NTildei, h1i, h2i, c)
	assert.True(t, ok, "proof must verify")
}
