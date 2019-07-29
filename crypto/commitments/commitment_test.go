package commitments_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/binance-chain/tss-lib/crypto/commitments"
)

func TestCreateVerify(t *testing.T) {
	one := big.NewInt(1)
	zero := big.NewInt(0)

	commitment := NewHashCommitment(zero, one)
	pass := commitment.Verify()

	assert.True(t, pass, "must pass")
}

func TestDeCommit(t *testing.T) {
	one := big.NewInt(1)
	zero := big.NewInt(0)

	commitment := NewHashCommitment(zero, one)
	pass, secrets := commitment.DeCommit()

	assert.True(t, pass, "must pass")

	assert.NotZero(t, len(secrets), "len(secrets) must be non-zero")
}
