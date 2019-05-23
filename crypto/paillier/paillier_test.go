package paillier

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/math"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	PaillierKeyLength = 2048
)

func TestGenerateKeyPair(t *testing.T) {
	publicKey, privateKey := GenerateKeyPair(PaillierKeyLength)
	t.Log(publicKey)
	t.Log(privateKey)
}

func TestEncrypt(t *testing.T) {
	publicKey, _ := GenerateKeyPair(PaillierKeyLength)

	one := big.NewInt(1)

	cipher, _, _ := publicKey.Encrypt(one)
	t.Log(cipher)
}

func TestDecrypt(t *testing.T) {
	publicKey, privateKey := GenerateKeyPair(PaillierKeyLength)

	num := math.GetRandomPositiveInt(publicKey.N)
	t.Log(num)

	cipher, _, _ := publicKey.Encrypt(num)

	m, err := privateKey.Decrypt(cipher)

	assert.NoError(t, err, "must not error")

	t.Log(m)
}

func TestHomoAdd(t *testing.T) {
	publicKey, privateKey := GenerateKeyPair(PaillierKeyLength)

	num1 := big.NewInt(10)
	num2 := big.NewInt(32)

	sum := new(big.Int).Add(num1, num2)
	sum = new(big.Int).Mod(sum, publicKey.N)

	one, _, _ := publicKey.Encrypt(num1)
	two, _, _ := publicKey.Encrypt(num2)

	ciphered := publicKey.HomoAdd(one, two)

	plain, _ := privateKey.Decrypt(ciphered)

	assert.Equal(t, new(big.Int).Add(num1, num2), plain)
}

func TestProof(t *testing.T) {
	_, privateKey := GenerateKeyPair(PaillierKeyLength)

	zkFactProof := privateKey.Proof()

	t.Log(zkFactProof)
}

func TestVerifyProof(t *testing.T) {
	publicKey, privateKey := GenerateKeyPair(PaillierKeyLength)

	proof := privateKey.Proof()

	res := proof.Verify(publicKey)

	assert.True(t, res, "zk fact verify result must be true")
}
