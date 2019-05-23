package schnorrZK_test

import (
	"math/big"
	"testing"

	s256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/math"
	"github.com/binance-chain/tss-lib/crypto/schnorrZK"
)

func TestZKProve(t *testing.T) {
	u := math.GetRandomPositiveInt(schnorrZK.EC.N)
	proof := schnorrZK.ZKProve(u)

	t.Log(proof)
}

func TestZKVerify(t *testing.T) {
	u := math.GetRandomPositiveInt(schnorrZK.EC.N)

	uGx, uGy := s256k1.S256().ScalarBaseMult(u.Bytes())
	uG := []*big.Int{uGx, uGy}

	proof := schnorrZK.ZKProve(u)

	res := schnorrZK.ZKVerify(uG, proof)

	assert.True(t, res, "verify result must be true")
}
