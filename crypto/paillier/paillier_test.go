package paillier

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/math"
)

const KeyPairLength = 2048

func TestGenerateKeyPair(t *testing.T) {
	publicKey, privateKey := GenerateKeyPair(KeyPairLength)
	t.Log(publicKey)
	t.Log(privateKey)
}

func TestEncrypt(t *testing.T) {
	publicKey, _ := GenerateKeyPair(KeyPairLength)

	one := big.NewInt(1)

	cipher, _,_ := publicKey.Encrypt(one)
	t.Log(cipher)
}

func TestDecrypt(t *testing.T) {
	publicKey, privateKey := GenerateKeyPair(KeyPairLength)

	num := math.GetRandomPositiveInt(publicKey.N)
	t.Log(num)

	cipher, _,_ := publicKey.Encrypt(num)

	m, err := privateKey.Decrypt(cipher)

	assert.NoError(t, err, "must not error")

	t.Log(m)
}

func TestHomoAdd(t *testing.T) {
	publicKey, privateKey := GenerateKeyPair(KeyPairLength)

	num1 := big.NewInt(10)
	num2 := big.NewInt(32)

	sum := new(big.Int).Add(num1, num2)
	sum = new(big.Int).Mod(sum, publicKey.N)

	one, _,_ := publicKey.Encrypt(num1)
	two, _,_ := publicKey.Encrypt(num2)

	ciphered := publicKey.HomoAdd(one, two)

	plain, _ := privateKey.Decrypt(ciphered)

	assert.Equal(t, new(big.Int).Add(num1, num2), plain)
}

func TestZKFactProve(t *testing.T) {
	_, privateKey := GenerateKeyPair(KeyPairLength)

	zkFactProof := privateKey.ZKFactProve()

	t.Log(zkFactProof)
}

func TestZKFactVerify(t *testing.T) {
	publicKey, privateKey := GenerateKeyPair(KeyPairLength)

	zkFactProof := privateKey.ZKFactProve()

	res := publicKey.ZKFactVerify(zkFactProof)

	assert.True(t, res, "zk fact verify result must be true")
}
