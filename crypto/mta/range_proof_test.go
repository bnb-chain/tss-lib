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
	testPaillierKeyLength = 2048
)

func TestProveRangeAlice(t *testing.T) {
	sk, pk := paillier.GenerateKeyPair(testPaillierKeyLength)
	// ki := random.MustGetRandomInt(256)
	// ecdsaSk := random.GetRandomPrimeInt(256)
	// ecdsaPKX, ecdsaPKY := tss.EC().ScalarBaseMult(ecdsaSk.Bytes())
	m := random.GetRandomPositiveInt(tss.EC().Params().N)

	c, r, err := sk.EncryptAndReturnRandomness(m)
	assert.NoError(t, err)

	primes := []*big.Int{random.GetRandomPrimeInt(256), random.GetRandomPrimeInt(256)}
	NTildei, h1i, h2i, err := keygen.GenerateNTildei(primes)
	rangeProofAlice := ProveRangeAlice(pk, c, NTildei, h1i, h2i, m, r)
	assert.NoError(t, err)
	t.Log(rangeProofAlice)
}
