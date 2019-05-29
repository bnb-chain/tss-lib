package schnorrZK_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/math"
	"github.com/binance-chain/tss-lib/crypto/schnorrZK"
)

func TestZKProve(t *testing.T) {
	u := math.GetRandomPositiveInt(schnorrZK.EC.N)
	proof := schnorrZK.NewZKProof(u)

	assert.NotZero(t, proof.E)
	assert.NotZero(t, proof.S)
}

func TestZKVerify(t *testing.T) {
	u := math.GetRandomPositiveInt(schnorrZK.EC.N)

	uGx, uGy := schnorrZK.EC.ScalarBaseMult(u.Bytes())
	uG := []*big.Int{uGx, uGy}

	proof := schnorrZK.NewZKProof(u)
	res := proof.Verify(uG)

	assert.True(t, res, "verify result must be true")
}

func TestZKVerifyBad(t *testing.T) {
	u  := math.GetRandomPositiveInt(schnorrZK.EC.N)
	u2 := math.GetRandomPositiveInt(schnorrZK.EC.N)

	uGx, uGy := schnorrZK.EC.ScalarBaseMult(u.Bytes())
	uG := []*big.Int{uGx, uGy}

	proof := schnorrZK.NewZKProof(u2)
	res := proof.Verify(uG)

	assert.False(t, res, "verify result must be false")
}
