// The Paillier Crypto-system is an additive crypto-system. This means that given two ciphertexts, one can perform operations equivalent to adding the respective plain texts.
// Additionally, Paillier Crypto-system supports further computations:
//
// * Encrypted integers can be added together
// * Encrypted integers can be multiplied by an unencrypted integer
// * Encrypted integers and unencrypted integers can be added together
//
// Implementation adheres to GG18Spec (6)

package paillier

import (
	"errors"
	"fmt"
	gmath "math"
	"math/big"
	"strconv"

	"github.com/otiai10/primes"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/common/random"
	crypto2 "github.com/binance-chain/tss-lib/crypto"
)

const (
	ProofIters        = 13
	verifyPrimesUntil = 1000 // Verify uses primes <1000
)

type (
	PublicKey struct {
		N, PhiN *big.Int
	}

	PrivateKey struct {
		PublicKey
		LambdaN *big.Int // lcm(p-1, q-1)
	}

	// Proof uses the new GenerateXs method in GG18Spec (6)
	Proof []*big.Int
)

var (
	ErrMessageTooLong = fmt.Errorf("the message is too large or < 0")

	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

func init() {
	// init primes cache
	_ = primes.Globally.Until(verifyPrimesUntil)
}

// len is the length of the modulus (each prime = len / 2)
func GenerateKeyPair(len int) (privateKey *PrivateKey, publicKey *PublicKey) {
	P, Q := random.GetRandomPrimeInt(len/2), random.GetRandomPrimeInt(len/2)
	N := new(big.Int).Mul(P, Q)
	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)

	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)

	publicKey = &PublicKey{N: N, PhiN: phiN}
	privateKey = &PrivateKey{PublicKey: *publicKey, LambdaN: lambdaN}
	return
}

// ----- //

func (publicKey *PublicKey) EncryptAndReturnRandomness(m *big.Int) (c *big.Int, x *big.Int, err error) {
	if m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
		return nil, nil, ErrMessageTooLong
	}
	x = random.GetRandomPositiveRelativelyPrimeInt(publicKey.N)
	N2 := publicKey.NSquare()
	// 1. gamma^m mod N2
	Gm := new(big.Int).Exp(publicKey.Gamma(), m, N2)
	// 2. x^N mod N2
	xN := new(big.Int).Exp(x, publicKey.N, N2)
	// 3. (1) * (2) mod N2
	c = common.ModInt(N2).Mul(Gm, xN)
	return
}

func (publicKey *PublicKey) Encrypt(m *big.Int) (c *big.Int, err error) {
	c, _, err = publicKey.EncryptAndReturnRandomness(m)
	return
}

func (publicKey *PublicKey) HomoMult(m, c1 *big.Int) (*big.Int, error) {
	if m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
		return nil, ErrMessageTooLong
	}
	N2 := publicKey.NSquare()
	if c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { // c1 < 0 || c1 >= N2 ?
		return nil, ErrMessageTooLong
	}
	// cipher^m mod N2
	return common.ModInt(N2).Exp(c1, m), nil
}

func (publicKey *PublicKey) HomoAdd(c1, c2 *big.Int) (*big.Int, error) {
	N2 := publicKey.NSquare()
	if c1.Cmp(zero) == -1 || c1.Cmp(N2) != -1 { // c1 < 0 || c1 >= N2 ?
		return nil, ErrMessageTooLong
	}
	if c2.Cmp(zero) == -1 || c2.Cmp(N2) != -1 { // c2 < 0 || c2 >= N2 ?
		return nil, ErrMessageTooLong
	}
	// c1 * c2 mod N2
	return common.ModInt(N2).Mul(c1, c2), nil
}

func (publicKey *PublicKey) NSquare() *big.Int {
	return new(big.Int).Mul(publicKey.N, publicKey.N)
}

// AsInts returns the PublicKey serialised to a slice of *big.Int for hashing
func (publicKey *PublicKey) AsInts() []*big.Int {
	return []*big.Int{publicKey.N, publicKey.Gamma(), publicKey.PhiN}
}

// Gamma returns N+1
func (publicKey *PublicKey) Gamma() *big.Int {
	return new(big.Int).Add(publicKey.N, one)
}

// ----- //

func (privateKey *PrivateKey) Decrypt(c *big.Int) (m *big.Int, err error) {
	N2 := privateKey.NSquare()
	if c.Cmp(zero) == -1 || c.Cmp(N2) != -1 { // c < 0 || c >= N2 ?
		return nil, ErrMessageTooLong
	}
	// 1. L(u) = (c^LambdaN-1 mod N2) / N
	Lc := L(new(big.Int).Exp(c, privateKey.LambdaN, N2), privateKey.N)
	// 2. L(u) = (Gamma^LambdaN-1 mod N2) / N
	Lg := L(new(big.Int).Exp(privateKey.Gamma(), privateKey.LambdaN, N2), privateKey.N)
	// 3. (1) * modInv(2) mod N
	inv := new(big.Int).ModInverse(Lg, privateKey.N)
	m = common.ModInt(privateKey.N).Mul(Lc, inv)
	return
}

// ----- //

// Proof is an implementation of Gennaro, R., Micciancio, D., Rabin, T.:
// An efficient non-interactive statistical zero-knowledge proof system for quasi-safe prime products.
// In: In Proc. of the 5th ACM Conference on Computer and Communications Security (CCS-98. Citeseer (1998)

func (privateKey *PrivateKey) Proof(k *big.Int, ecdsaPub *crypto2.ECPoint) Proof {
	iters := ProofIters
	pi := make(Proof, iters)
	xs := GenerateXs(iters, k, privateKey.N, ecdsaPub)
	for i := 0; i < iters; i++ {
		M := new(big.Int).ModInverse(privateKey.N, privateKey.PhiN)
		pi[i] = new(big.Int).Exp(xs[i], M, privateKey.N)
	}
	return pi
}

func (proof Proof) Verify(pkN, k *big.Int, ecdsaPub *crypto2.ECPoint) (bool, error) {
	iters := ProofIters
	pch, xch := make(chan bool, 1), make(chan []*big.Int, 1) // buffered to allow early exit
	prms := primes.Until(verifyPrimesUntil).List()           // uses cache primed in init()
	go func(ch chan<- bool) {
		for _, prm := range prms {
			// If prm divides N then Return 0
			if new(big.Int).Mod(pkN, big.NewInt(prm)).Cmp(zero) == 0 {
				ch <- false // is divisible
				return
			}
		}
		ch <- true
	}(pch)
	go func(ch chan<- []*big.Int) {
		ch <- GenerateXs(iters, k, pkN, ecdsaPub)
	}(xch)
	for j := 0; j < 2; j++ {
		select {
		case ok := <-pch:
			if !ok {
				return false, nil
			}
		case xs := <-xch:
			if len(xs) != iters {
				return false, fmt.Errorf("paillier proof verify: expected %d xs but got %d", iters, len(xs))
			}
			for i, xi := range xs {
				xiModN := new(big.Int).Mod(xi, pkN)
				yiExpN := new(big.Int).Exp(proof[i], pkN, pkN)
				if xiModN.Cmp(yiExpN) != 0 {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

// ----- utils

func L(u, N *big.Int) *big.Int {
	t := new(big.Int).Sub(u, one)
	return new(big.Int).Div(t, N)
}

// GenerateXs generates the challenges used in Paillier key Proof
func GenerateXs(m int, k, N *big.Int, ecdsaPub *crypto2.ECPoint) []*big.Int {
	var i, n int
	ret := make([]*big.Int, m)
	sX, sY := ecdsaPub.X(), ecdsaPub.Y()
	kb, sXb, sYb, Nb := k.Bytes(), sX.Bytes(), sY.Bytes(), N.Bytes()
	bits := N.BitLen()
	blocks := int(gmath.Ceil(float64(bits) / 256))
	chs := make([]chan []byte, blocks)
	for k := range chs {
		chs[k] = make(chan []byte)
	}
	for i < m {
		xi := make([]byte, 0, blocks*32)
		ib := []byte(strconv.Itoa(i))
		nb := []byte(strconv.Itoa(n))
		for j := 0; j < blocks; j++ {
			go func(j int) {
				jBz := []byte(strconv.Itoa(j))
				hash := common.SHA512_256(ib, jBz, nb, kb, sXb, sYb, Nb)
				chs[j] <- hash
			}(j)
		}
		for _, ch := range chs { // must be in order
			rx := <-ch
			if rx == nil { // this should never happen. see: https://golang.org/pkg/hash/#Hash
				panic(errors.New("GenerateXs hash write error!"))
			}
			xi = append(xi, rx...) // xi1||···||xib
		}
		ret[i] = new(big.Int).SetBytes(xi)
		if random.IsNumberInMultiplicativeGroup(N, ret[i]) {
			i++
		} else {
			n++
		}
	}
	return ret
}
