// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package paillier_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	. "github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

func TestGenerateKeyPair(t *testing.T) {
	privateKey, publicKey := GenerateKeyPair(testPaillierKeyLength)

	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	t.Log(privateKey)
}

func TestEncrypt(t *testing.T) {
	_, publicKey := GenerateKeyPair(testPaillierKeyLength)
	cipher, err := publicKey.Encrypt(big.NewInt(1))

	assert.NoError(t, err, "must not error")
	assert.NotZero(t, cipher)
	t.Log(cipher)
}

func TestEncryptDecrypt(t *testing.T) {
	for i := 1; i < 10; i++ {
		privateKey, _ := GenerateKeyPair(testPaillierKeyLength)

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

func TestHomoMul(t *testing.T) {
	privateKey, _ := GenerateKeyPair(testPaillierKeyLength)

	three, err := privateKey.Encrypt(big.NewInt(3))
	assert.NoError(t, err)

	// for HomoMul, the first argument `m` is not ciphered
	six := big.NewInt(6)

	cm, err := privateKey.HomoMult(six, three)
	assert.NoError(t, err)
	multiple, err := privateKey.Decrypt(cm)
	assert.NoError(t, err)

	// 3 * 6 = 18
	exp := int64(18)
	assert.Equal(t, 0, multiple.Cmp(big.NewInt(exp)))
}

func TestHomoAdd(t *testing.T) {
	privateKey, publicKey := GenerateKeyPair(testPaillierKeyLength)

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

func TestProof(t *testing.T) {
	privateKey, _ := GenerateKeyPair(testPaillierKeyLength)
	ki := common.MustGetRandomInt(256)                     // index
	ui := common.GetRandomPositiveInt(tss.EC().Params().N) // ECDSA private
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())          // ECDSA public
	proof := privateKey.Proof(ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	for _, yi := range proof {
		assert.NotZero(t, yi)
		// TODO add a better assertion
	}
	t.Log(proof)
}

func TestProofVerify(t *testing.T) {
	privateKey, publicKey := GenerateKeyPair(testPaillierKeyLength)
	ki := common.MustGetRandomInt(256)                     // index
	ui := common.GetRandomPositiveInt(tss.EC().Params().N) // ECDSA private
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())          // ECDSA public
	proof := privateKey.Proof(ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	res, err := proof.Verify(publicKey.N, ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	assert.NoError(t, err)
	assert.True(t, res, "proof verify result must be true")
}

func TestProofVerifyFail(t *testing.T) {
	privateKey, publicKey := GenerateKeyPair(testPaillierKeyLength)
	ki := common.MustGetRandomInt(256)                     // index
	ui := common.GetRandomPositiveInt(tss.EC().Params().N) // ECDSA private
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())          // ECDSA public
	proof := privateKey.Proof(ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	last := proof[len(proof)-1]
	last.Sub(last, big.NewInt(1))
	res, err := proof.Verify(publicKey.N, ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	assert.NoError(t, err)
	assert.False(t, res, "proof verify result must be true")
}

func TestComputeL(t *testing.T) {
	u := big.NewInt(21)
	n := big.NewInt(3)

	expected := big.NewInt(6)
	actual := L(u, n)

	assert.Equal(t, 0, expected.Cmp(actual))
}

func TestGenerateXs(t *testing.T) {
	k := common.MustGetRandomInt(256)
	sX := common.MustGetRandomInt(256)
	sY := common.MustGetRandomInt(256)
	N := common.GetRandomPrimeInt(2048)

	xs := GenerateXs(13, k, N, crypto.NewECPointNoCurveCheck(tss.EC(), sX, sY))
	assert.Equal(t, 13, len(xs))
	for _, xi := range xs {
		assert.True(t, common.IsNumberInMultiplicativeGroup(N, xi))
	}
}
