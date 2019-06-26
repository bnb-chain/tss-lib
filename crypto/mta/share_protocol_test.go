package mta

import(
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

func TestShareProtocol(t *testing.T) {
	q := tss.EC().Params().N

	sk, pk := paillier.GenerateKeyPair(testPaillierKeyLength)

	a := random.GetRandomPositiveInt(q)
	b := random.GetRandomPositiveInt(q)

	cA, err := AliceInit(pk, a, nil, nil, nil)
	assert.NoError(t, err)

	_, cB, _, beta1, err := BobMid(pk, b, cA, nil, nil, nil, nil, nil, nil)
	assert.NoError(t, err)

	alpha, err := AliceEnd(pk, nil, nil, nil, nil, cB, nil, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + beta1
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, beta1)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))
}
