// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

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
	"runtime"
	"strconv"
	"time"

	"github.com/otiai10/primes"

	"github.com/binance-chain/tss-lib/common"
	crypto2 "github.com/binance-chain/tss-lib/crypto"
)

const (
	ProofIters         = 13
	verifyPrimesUntil  = 1000 // Verify uses primes <1000
	pQBitLenDifference = 3    // >1020-bit P-Q
)

type (
	PublicKey struct {
		N *big.Int
	}

	PrivateKey struct {
		PublicKey
		LambdaN, // lcm(p-1, q-1)
		PhiN *big.Int // (p-1) * (q-1)
	}

	// Proof uses the new GenerateXs method in GG18Spec (6)
	Proof [ProofIters]*big.Int
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
func GenerateKeyPair(modulusBitLen int, timeout time.Duration, optionalConcurrency ...int) (privateKey *PrivateKey, publicKey *PublicKey, err error) {
	var concurrency int
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			panic(errors.New("GeneratePreParams: expected 0 or 1 item in `optionalConcurrency`"))
		}
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.NumCPU()
	}

	// KS-BTL-F-03: use two safe primes for P, Q
	var P, Q, N *big.Int
	{
		tmp := new(big.Int)
		for {
			sgps, err := common.GetRandomSafePrimesConcurrent(modulusBitLen/2, 2, timeout, concurrency)
			if err != nil {
				return nil, nil, err
			}
			P, Q = sgps[0].SafePrime(), sgps[1].SafePrime()
			// KS-BTL-F-03: check that p-q is also very large in order to avoid square-root attacks
			if tmp.Sub(P, Q).BitLen() >= (modulusBitLen/2)-pQBitLenDifference {
				break
			}
		}
		N = tmp.Mul(P, Q)
	}

	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)

	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)

	publicKey = &PublicKey{N: N}
	privateKey = &PrivateKey{PublicKey: *publicKey, LambdaN: lambdaN, PhiN: phiN}
	return
}

// ----- //

func (pk *PublicKey) EncryptWithChosenRandomness(m, x *big.Int) (c *big.Int, err error) {
	if x == nil || x.Cmp(zero) == 0 {
		return nil, errors.New("EncryptWithChosenRandomness() requires non-zero randomness")
	}
	if m.Cmp(zero) == -1 || m.Cmp(pk.N) != -1 { // m < 0 || m >= N ?
		return nil, ErrMessageTooLong
	}
	// https://docs.rs/paillier/0.2.0/src/paillier/core.rs.html#236
	modNSq := common.ModInt(pk.NSquare())
	// 1. gamma^m mod N2
	Gm := modNSq.Exp(pk.Gamma(), m)
	// 2. x^N mod N2
	xN := modNSq.Exp(x, pk.N)
	// 3. (1) * (2) mod N2
	c = modNSq.Mul(Gm, xN)
	return
}

func (pk *PublicKey) EncryptAndReturnRandomness(m *big.Int) (c *big.Int, x *big.Int, err error) {
	if m.Cmp(zero) == -1 || m.Cmp(pk.N) != -1 { // m < 0 || m >= N ?
		return nil, nil, ErrMessageTooLong
	}
	modNSq := common.ModInt(pk.NSquare())
	x = common.GetRandomPositiveRelativelyPrimeInt(pk.N)
	// 1. gamma^m mod N2
	Gm := modNSq.Exp(pk.Gamma(), m)
	// 2. x^N mod N2
	xN := modNSq.Exp(x, pk.N)
	// 3. (1) * (2) mod N2
	c = modNSq.Mul(Gm, xN)
	return
}

func (pk *PublicKey) Encrypt(m *big.Int) (c *big.Int, err error) {
	c, _, err = pk.EncryptAndReturnRandomness(m)
	return
}

func (pk *PublicKey) HomoMult(m, c1 *big.Int) (*big.Int, error) {
	if m.Cmp(zero) == -1 || m.Cmp(pk.N) != -1 { // m < 0 || m >= N ?
		return nil, ErrMessageTooLong
	}
	NSq := pk.NSquare()
	if c1.Cmp(zero) == -1 || c1.Cmp(NSq) != -1 { // c1 < 0 || c1 >= N2 ?
		return nil, ErrMessageTooLong
	}
	// cipher^m mod N2
	return common.ModInt(NSq).Exp(c1, m), nil
}

func (pk *PublicKey) HomoAdd(c1, c2 *big.Int) (*big.Int, error) {
	NSq := pk.NSquare()
	if c1.Cmp(zero) == -1 || c1.Cmp(NSq) != -1 { // c1 < 0 || c1 >= N2 ?
		return nil, ErrMessageTooLong
	}
	if c2.Cmp(zero) == -1 || c2.Cmp(NSq) != -1 { // c2 < 0 || c2 >= N2 ?
		return nil, ErrMessageTooLong
	}
	// c1 * c2 mod N2
	return common.ModInt(NSq).Mul(c1, c2), nil
}

func (pk *PublicKey) NSquare() *big.Int {
	return new(big.Int).Mul(pk.N, pk.N)
}

// AsInts returns the PublicKey serialised to a slice of *big.Int for hashing
func (pk *PublicKey) AsInts() []*big.Int {
	return []*big.Int{pk.N, pk.Gamma()}
}

// Gamma returns N+1
func (pk *PublicKey) Gamma() *big.Int {
	return new(big.Int).Add(pk.N, one)
}

// ----- //

func (sk *PrivateKey) Decrypt(c *big.Int) (m *big.Int, err error) {
	NSq := sk.NSquare()
	modN := common.ModInt(sk.N)
	modNSq := common.ModInt(NSq)
	if c.Cmp(zero) == -1 || c.Cmp(NSq) != -1 { // c < 0 || c >= N2 ?
		return nil, ErrMessageTooLong
	}
	// 1. L(u) = (c^LambdaN-1 mod N2) / N
	Lc := L(modNSq.Exp(c, sk.LambdaN), sk.N)
	// 2. L(u) = (Gamma^LambdaN-1 mod N2) / N
	Lg := L(modNSq.Exp(sk.Gamma(), sk.LambdaN), sk.N)
	// 3. (1) * modInv(2) mod N
	inv := modN.Inverse(Lg)
	m = modN.Mul(Lc, inv)
	return
}

func (sk *PrivateKey) DecryptAndRecoverRandomness(c *big.Int) (m, x *big.Int, err error) {
	if m, err = sk.Decrypt(c); err != nil {
		return
	}
	modN := common.ModInt(sk.N)
	modNSq := common.ModInt(sk.NSquare())
	modPhiN := common.ModInt(sk.PhiN)
	// CDash = C * (1 - m*N) mod N2  (this is scalar subtraction)
	mN := modNSq.Mul(m, sk.N)
	cDash := modNSq.Mul(c, new(big.Int).Sub(one, mN))
	// M = N^-1 mod phi(N)
	M := modPhiN.Inverse(sk.N)
	// x = CDash^M mod N
	x = modN.Exp(cDash, M)
	return
}

// ----- //

// Proof is an implementation of Gennaro, R., Micciancio, D., Rabin, T.:
// An efficient non-interactive statistical zero-knowledge proof system for quasi-safe prime products.
// In: In Proc. of the 5th ACM Conference on Computer and Communications Security (CCS-98. Citeseer (1998)

func (sk *PrivateKey) Proof(k *big.Int, ecdsaPub *crypto2.ECPoint) Proof {
	var pi Proof
	iters := ProofIters
	xs := GenerateXs(iters, k, sk.N, ecdsaPub)
	for i := 0; i < iters; i++ {
		M := new(big.Int).ModInverse(sk.N, sk.PhiN)
		pi[i] = new(big.Int).Exp(xs[i], M, sk.N)
	}
	return pi
}

func (pf Proof) Verify(pkN, k *big.Int, ecdsaPub *crypto2.ECPoint) (bool, error) {
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
				yiExpN := new(big.Int).Exp(pf[i], pkN, pkN)
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
		if common.IsNumberInMultiplicativeGroup(N, ret[i]) {
			i++
		} else {
			n++
		}
	}
	return ret
}
