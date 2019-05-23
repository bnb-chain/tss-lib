// The Paillier Crypto-system is an additive crypto-system. This means that given two ciphertexts, one can perform operations equivalent to adding the respective plain texts.
// Additionally, Paillier Crypto-system supports further computations:
//
// * Encrypted integers can be added together
// * Encrypted integers can be multiplied by an unencrypted integer
// * Encrypted integers and unencrypted integers can be added together

package paillier

import (
	"fmt"
	"math/big"

	"golang.org/x/crypto/sha3"

	"github.com/binance-chain/tss-lib/common/math"
)

var ErrMessageTooLong = fmt.Errorf("the message is too long")

type (
	PublicKey struct {
		Length   int
		N        *big.Int // modulus
		G        *big.Int // n+1, since p and q are same length
		NSquared *big.Int // NSquared = N * N
	}

	PrivateKey struct {
		PublicKey
		Length int
		L *big.Int // (p-1)*(q-1)
		U *big.Int // L^-1 mod N
	}

	Proof struct {
		H1 *big.Int
		H2 *big.Int
		Y  *big.Int
		E  *big.Int
		N  *big.Int
	}
)

// len is the length of the modulus (two primes)
func GenerateKeyPair(len int) (*PublicKey, *PrivateKey) {
	one := big.NewInt(1)

	p := math.GetRandomPrimeInt(len / 2)
	q := math.GetRandomPrimeInt(len / 2)

	n  := new(big.Int).Mul(p, q)
	n2 := new(big.Int).Mul(n, n)
	g  := new(big.Int).Add(n, one)

	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)

	l := new(big.Int).Mul(pMinus1, qMinus1)
	u := new(big.Int).ModInverse(l, n)

	publicKey  := &PublicKey{Length: len, N: n, G: g, NSquared: n2}
	privateKey := &PrivateKey{Length: len, PublicKey: *publicKey, L: l, U: u}

	return publicKey, privateKey
}

func (publicKey *PublicKey) Encrypt(m *big.Int) (*big.Int, *big.Int, error) {
	if m.Cmp(publicKey.N) > 0 {
		return nil, nil,ErrMessageTooLong
	}

	rndStar := math.GetRandomPositiveIntStar(publicKey.N)

	// G^m mod NSq
	Gm := new(big.Int).Exp(publicKey.G, m, publicKey.NSquared)
	// R^N mod NSq
	RN := new(big.Int).Exp(rndStar, publicKey.N, publicKey.NSquared)
	// G^m * R^n
	GmRN := new(big.Int).Mul(Gm, RN)
	// G^m * R^n mod NSq
	cipher := new(big.Int).Mod(GmRN, publicKey.NSquared)

	return cipher, rndStar,nil
}

func (privateKey *PrivateKey) Decrypt(cipher *big.Int) (*big.Int, error) {
	one := big.NewInt(1)

	if cipher.Cmp(privateKey.NSquared) > 0 {
		return nil, ErrMessageTooLong
	}

	// c^L mod NSq
	cL := new(big.Int).Exp(cipher, privateKey.L, privateKey.NSquared)
	// c^L-1
	cLMinus1 := new(big.Int).Sub(cL, one)
	// (c^L-1) / N
	cLMinus1DivN := new(big.Int).Div(cLMinus1, privateKey.N)
	// (c^L-1) / N*U
	cLMinus1DivNMulU := new(big.Int).Mul(cLMinus1DivN, privateKey.U)
	// (c^L-1) / N*U mod N
	mBigInt := new(big.Int).Mod(cLMinus1DivNMulU, privateKey.N)

	return mBigInt, nil
}

func (publicKey *PublicKey) HomoAdd(c1, c2 *big.Int) *big.Int {
	// c1 * c2
	c1c2 := new(big.Int).Mul(c1, c2)
	// c1 * c2 mod NSq
	newCipher := new(big.Int).Mod(c1c2, publicKey.NSquared)

	return newCipher
}

// TODO add Homo Multiply method

func (privateKey *PrivateKey) Proof() *Proof {
	h1 := math.GetRandomPositiveIntStar(privateKey.N)
	h2 := math.GetRandomPositiveIntStar(privateKey.N)
	r := math.GetRandomPositiveInt(privateKey.N)

	h1R := new(big.Int).Exp(h1, r, privateKey.N)
	h2R := new(big.Int).Exp(h2, r, privateKey.N)

	sha3256 := sha3.New256()
	sha3256.Write(h1R.Bytes())
	sha3256.Write(h2R.Bytes())
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	y := new(big.Int).Add(privateKey.N, privateKey.L)
	y = new(big.Int).Mul(y, e)
	y = new(big.Int).Add(y, r)

	return &Proof{H1: h1, H2: h2, Y: y, E: e,N: privateKey.N}
}

func (proof *Proof) Verify(publicKey *PublicKey) bool {
	ySubNE := new(big.Int).Mul(publicKey.N, proof.E)
	ySubNE = new(big.Int).Sub(proof.Y, ySubNE)

	h1R := new(big.Int).Exp(proof.H1, ySubNE, publicKey.N)
	h2R := new(big.Int).Exp(proof.H2, ySubNE, publicKey.N)

	sha3256 := sha3.New256()
	sha3256.Write(h1R.Bytes())
	sha3256.Write(h2R.Bytes())
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	if e.Cmp(proof.E) == 0 {
		return true
	} else {
		return false
	}
}
