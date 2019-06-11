package paillier_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/random"
	. "github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/keygen"
	"github.com/binance-chain/tss-lib/types"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	PaillierKeyLength = 2048
)

func TestGenerateKeyPair(t *testing.T) {
	publicKey, privateKey := GenerateKeyPair(PaillierKeyLength)

	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	t.Log(privateKey)
}

func TestEncrypt(t *testing.T) {
	publicKey, _ := GenerateKeyPair(PaillierKeyLength)
	cipher, err := publicKey.Encrypt(big.NewInt(1))

	assert.NoError(t, err, "must not error")
	assert.NotZero(t, cipher)
	t.Log(cipher)
}

func TestEncryptDecrypt(t *testing.T) {
	for i := 1; i < 10; i++ {
		privateKey, _ := GenerateKeyPair(PaillierKeyLength)

		exp := big.NewInt(100)
		cypher, err := privateKey.Encrypt(exp)
		if err != nil {
			t.Error(err)
		}
		ret, err := privateKey.Decrypt(cypher)
		assert.NoError(t, err)
		assert.Equal(t, 0, exp.Cmp(ret),
			"wrong decryption ", ret, " is not ", exp)
	}
}

func TestHomoAdd(t *testing.T) {
	privateKey, publicKey := GenerateKeyPair(PaillierKeyLength)

	num1 := big.NewInt(10)
	num2 := big.NewInt(32)

	sum := new(big.Int).Add(num1, num2)
	sum = new(big.Int).Mod(sum, publicKey.N)

	one, _ := publicKey.Encrypt(num1)
	two, _ := publicKey.Encrypt(num2)

	ciphered, _ := publicKey.HomoAdd(one, two)

	plain, _ := privateKey.Decrypt(ciphered)

	assert.Equal(t, new(big.Int).Add(num1, num2), plain)
}

func TestHomoMul(t *testing.T) {
	privateKey, _ := GenerateKeyPair(PaillierKeyLength)

	three, err := privateKey.Encrypt(big.NewInt(3))
	assert.NoError(t, err)

	cm, err := privateKey.HomoMult(big.NewInt(6), three)
	assert.NoError(t, err)
	multiple, err := privateKey.Decrypt(cm)
	assert.NoError(t, err)

	// 3 * 6 = 18
	exp := int64(18)
	assert.Equal(t, 0, multiple.Cmp(big.NewInt(exp)))
}

func TestProof2(t *testing.T) {
	privateKey, _ := GenerateKeyPair(PaillierKeyLength)
	ki := random.MustGetRandomInt(256)               // index
	ui := random.GetRandomPositiveInt(keygen.EC().N) // ECDSA private
	yX, yY := keygen.EC().ScalarBaseMult(ui.Bytes()) // ECDSA public
	proof := privateKey.Proof2(ki, types.NewECPoint(yX, yY))
	for _, yi := range proof {
		assert.NotZero(t, yi)
		// TODO add a better assertion
	}
	t.Log(proof)
}

func TestProof2Verify2(t *testing.T) {
	privateKey, publicKey := GenerateKeyPair(PaillierKeyLength)
	ki := random.MustGetRandomInt(256)               // index
	ui := random.GetRandomPositiveInt(keygen.EC().N) // ECDSA private
	yX, yY := keygen.EC().ScalarBaseMult(ui.Bytes()) // ECDSA public
	proof := privateKey.Proof2(ki, types.NewECPoint(yX, yY))
	res, err := proof.Verify2(publicKey.N, ki, types.NewECPoint(yX, yY))
	assert.NoError(t, err)
	assert.True(t, res, "proof verify2 result must be true")
}

func TestProof2Verify2Fail(t *testing.T) {
	privateKey, publicKey := GenerateKeyPair(PaillierKeyLength)
	ki := random.MustGetRandomInt(256)               // index
	ui := random.GetRandomPositiveInt(keygen.EC().N) // ECDSA private
	yX, yY := keygen.EC().ScalarBaseMult(ui.Bytes()) // ECDSA public
	proof := privateKey.Proof2(ki, types.NewECPoint(yX, yY))
	last := proof[len(proof) - 1]
	last.Sub(last, big.NewInt(1))
	res, err := proof.Verify2(publicKey.N, ki, types.NewECPoint(yX, yY))
	assert.NoError(t, err)
	assert.False(t, res, "proof verify2 result must be true")
}

func TestComputeL(t *testing.T) {
	u := big.NewInt(21)
	n := big.NewInt(3)

	expected := big.NewInt(6)
	actual := L(u, n)

	assert.Equal(t, 0, expected.Cmp(actual))
}

func TestGenerateXs(t *testing.T) {
	k := random.MustGetRandomInt(256)
	sX := random.MustGetRandomInt(256)
	sY := random.MustGetRandomInt(256)
	N := random.GetRandomPrimeInt(2048)

	xs := GenerateXs(13, k, N, types.NewECPoint(sX, sY))
	assert.Equal(t, 13, len(xs))
	for _, xi := range xs {
		assert.True(t, random.IsNumberInMultiplicativeGroup(N, xi))
	}
}
