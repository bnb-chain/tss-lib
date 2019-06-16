package schnorrZK_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/random"
	. "github.com/binance-chain/tss-lib/crypto/schnorrZK"
	"github.com/binance-chain/tss-lib/tss"
)

func TestZKProve(t *testing.T) {
	u := random.GetRandomPositiveInt(tss.EC().Params().N)
	proof := NewZKProof(u)

	assert.NotZero(t, proof.E)
	assert.NotZero(t, proof.S)
}

func TestZKVerify(t *testing.T) {
	u := random.GetRandomPositiveInt(tss.EC().Params().N)

	uGx, uGy := tss.EC().ScalarBaseMult(u.Bytes())
	uG := []*big.Int{uGx, uGy}

	proof := NewZKProof(u)
	res := proof.Verify(uG)

	assert.True(t, res, "verify result must be true")
}

func TestZKVerifyBad(t *testing.T) {
	u  := random.GetRandomPositiveInt(tss.EC().Params().N)
	u2 := random.GetRandomPositiveInt(tss.EC().Params().N)

	uGx, uGy := tss.EC().ScalarBaseMult(u.Bytes())
	uG := []*big.Int{uGx, uGy}

	proof := NewZKProof(u2)
	res := proof.Verify(uG)

	assert.False(t, res, "verify result must be false")
}
