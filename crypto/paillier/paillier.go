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
	"context"
	"errors"
	"fmt"
	"io"
	gmath "math"
	"math/big"
	"runtime"
	"strconv"
	"sync"

	"github.com/otiai10/primes"

	"github.com/bnb-chain/tss-lib/v4/common"
	crypto2 "github.com/bnb-chain/tss-lib/v4/crypto"
)

const (
	ProofIters         = 13
	verifyPrimesUntil  = 1000 // Verify uses primes <1000
	pQBitLenDifference = 3    // >1020-bit P-Q
	// Minimum Paillier modulus bit length accepted by Proof.Verify. Matches
	// the GG18Spec recommendation and the paillierBitsLen used by the
	// keygen/resharing wire-format checks.
	verifyMinModulusBitLen = 2048
	// Miller-Rabin rounds for the composite check below; 30 gives ≤4^-30
	// false-positive rate against arbitrary composites — well below
	// cryptographic concern thresholds.
	verifyPrimalityRounds = 30
	// The smallest modulus GenerateKeyPair can produce at all. Below it the
	// |P-Q| retry loop does not merely take a long time, it cannot succeed.
	//
	// DERIVATION. Write h := modulusBitLen/2 for the width of each prime. The
	// retry accepts only when BitLen(P-Q) ≥ h - pQBitLenDifference, that is
	// |P-Q| ≥ 2^(h-4). common.GetRandomSafePrimesConcurrent sets the top two
	// bits of the (h-1)-bit Germain prime q, so every safe prime p = 2q+1 it can
	// return lies in [3·2^(h-2), 2^h) — a window of width 2^(h-2) — and the test
	// is therefore asking for two of its candidates a quarter of that window
	// apart. Enumerating the window exactly (q prime, 2q+1 prime, q in the top
	// quarter of h-1 bits) gives a single candidate for each of the three
	// smallest widths the safe-prime generator accepts: h=6 admits only p=59,
	// h=7 only p=107, h=8 only p=227. With one candidate both draws coincide,
	// |P-Q| = 0, and no number of rounds helps — for every modulusBitLen ≤ 17
	// the loop is unsatisfiable. h=9 is the first width with a spread wide
	// enough (3 candidates, farthest pair 36 apart against a threshold of 32),
	// so 2*9 = 18 is the exact floor: it refuses no size that could have
	// terminated. Above it the window fills in and acceptance settles at
	// ≈ (3/4)² = 0.56 per round, two near-uniform draws in a window of width W
	// being at least W/4 apart with that probability.
	minModulusBitLen = 18
)

type (
	PublicKey struct {
		N *big.Int
	}

	PrivateKey struct {
		PublicKey
		LambdaN, // lcm(p-1, q-1)
		PhiN *big.Int // (p-1) * (q-1)
		P, Q *big.Int

		// cached M = N^(-1) mod PhiN, lazily computed
		m     *big.Int
		mOnce sync.Once
	}

	// Proof uses the new GenerateXs method in GG18Spec (6)
	Proof [ProofIters]*big.Int
)

var (
	ErrMessageTooLong   = fmt.Errorf("the message is too large or < 0")
	ErrMessageMalFormed = fmt.Errorf("the message is mal-formed")
	ErrModulusMalFormed = fmt.Errorf("the public key modulus is mal-formed")

	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

func init() {
	// init primes cache
	_ = primes.Globally.Until(verifyPrimesUntil)
}

// len is the length of the modulus (each prime = len / 2)
func GenerateKeyPair(ctx context.Context, rand io.Reader, modulusBitLen int, optionalConcurrency ...int) (privateKey *PrivateKey, publicKey *PublicKey, err error) {
	if modulusBitLen < minModulusBitLen {
		return nil, nil, fmt.Errorf("GenerateKeyPair: modulusBitLen must be at least %d, got %d", minModulusBitLen, modulusBitLen)
	}
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
			sgps, err := common.GetRandomSafePrimesConcurrent(ctx, modulusBitLen/2, 2, concurrency, rand)
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
	privateKey = &PrivateKey{PublicKey: *publicKey, LambdaN: lambdaN, PhiN: phiN, P: P, Q: Q}
	return
}

// ----- //

func (publicKey *PublicKey) EncryptAndReturnRandomness(rand io.Reader, m *big.Int) (c *big.Int, x *big.Int, err error) {
	if m.Cmp(zero) == -1 || m.Cmp(publicKey.N) != -1 { // m < 0 || m >= N ?
		return nil, nil, ErrMessageTooLong
	}
	x = common.GetRandomPositiveRelativelyPrimeInt(rand, publicKey.N)
	if x == nil {
		// (Z/NZ)* is empty, so there is no randomness to blind with. Only
		// reachable for N ≤ 1, which the m < N test above cannot catch on its
		// own: for N = 1 the one admissible m is 0.
		return nil, nil, ErrModulusMalFormed
	}
	N2 := publicKey.NSquare()
	// 1. gamma^m mod N2
	Gm := new(big.Int).Exp(publicKey.Gamma(), m, N2)
	// 2. x^N mod N2
	xN := new(big.Int).Exp(x, publicKey.N, N2)
	// 3. (1) * (2) mod N2
	c = common.ModInt(N2).Mul(Gm, xN)
	return
}

func (publicKey *PublicKey) Encrypt(rand io.Reader, m *big.Int) (c *big.Int, err error) {
	c, _, err = publicKey.EncryptAndReturnRandomness(rand, m)
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
	return []*big.Int{publicKey.N, publicKey.Gamma()}
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
	cg := new(big.Int).GCD(nil, nil, c, N2)
	if cg.Cmp(one) == 1 {
		return nil, ErrMessageMalFormed
	}

	var cExpLambda, gammaExpLambda *big.Int

	if common.IsConstantTimeEnabled() {
		// SECURITY: Use constant-time exponentiation to prevent timing side-channels.
		// The original code used math/big.Exp which leaks information about the secret
		// exponent LambdaN through execution time variations.
		// See: https://github.com/golang/go/issues/20654
		ctModN2 := common.NewCTModInt(N2)
		cExpLambda = ctModN2.ExpCT(c, privateKey.LambdaN)
		gammaExpLambda = ctModN2.ExpCT(privateKey.Gamma(), privateKey.LambdaN)
	} else {
		// Standard (non-constant-time) implementation for better performance
		cExpLambda = new(big.Int).Exp(c, privateKey.LambdaN, N2)
		gammaExpLambda = new(big.Int).Exp(privateKey.Gamma(), privateKey.LambdaN, N2)
	}

	// 1. L(u) = (c^LambdaN-1 mod N2) / N
	Lc := L(cExpLambda, privateKey.N)

	// 2. L(u) = (Gamma^LambdaN-1 mod N2) / N
	Lg := L(gammaExpLambda, privateKey.N)

	// 3. (1) * modInv(2) mod N
	var inv *big.Int
	if common.IsConstantTimeEnabled() {
		// SECURITY: Use constant-time ModInverse to prevent timing side-channels.
		// Lg is derived from secret LambdaN exponentiation.
		// N = P*Q is composite, so we must provide phi(N) for Euler's theorem.
		ctModN := common.NewCTModIntWithPhi(privateKey.N, privateKey.PhiN)
		inv = ctModN.ModInverseCT(Lg)
	} else {
		inv = new(big.Int).ModInverse(Lg, privateKey.N)
	}
	m = common.ModInt(privateKey.N).Mul(Lc, inv)
	return
}

// M returns the cached value of N^(-1) mod PhiN, computing it on first call.
func (privateKey *PrivateKey) M() *big.Int {
	privateKey.mOnce.Do(func() {
		privateKey.m = new(big.Int).ModInverse(privateKey.N, privateKey.PhiN)
	})
	return privateKey.m
}

// ----- //

// Proof is an implementation of Gennaro, R., Micciancio, D., Rabin, T.:
// An efficient non-interactive statistical zero-knowledge proof system for quasi-safe prime products.
// In: In Proc. of the 5th ACM Conference on Computer and Communications Security (CCS-98. Citeseer (1998)

func (privateKey *PrivateKey) Proof(k *big.Int, ecdsaPub *crypto2.ECPoint) Proof {
	var pi Proof
	iters := ProofIters
	xs := GenerateXs(iters, k, privateKey.N, ecdsaPub)

	// M = N^(-1) mod PhiN is precomputed and cached on the private key.
	M := privateKey.M()

	if common.IsConstantTimeEnabled() {
		// SECURITY: Use constant-time exponentiation for xs[i]^M mod N.
		// M is derived from secret PhiN, so we must use constant-time Exp.
		// N is odd, so bigmod works correctly here.
		ctModN := common.NewCTModInt(privateKey.N)
		for i := 0; i < iters; i++ {
			pi[i] = ctModN.ExpCT(xs[i], M)
		}
	} else {
		// Standard (non-constant-time) implementation for better performance
		for i := 0; i < iters; i++ {
			pi[i] = new(big.Int).Exp(xs[i], M, privateKey.N)
		}
	}
	return pi
}

// Verify checks a Paillier modulus proof produced by PrivateKey.Proof.
//
// pkN is the public Paillier modulus; k is a session-binding value
// (typically a PartyID key); ecdsaPub is the joint ECDSA public key from
// keygen. ecdsaPub's curve is consulted only via ecdsaPub.ValidateBasic
// (i.e. on-curve relative to the point's own stored curve). Callers that
// reuse this verifier outside the keygen flow — where tss.EC() is the
// implicit shared curve — should validate ecdsaPub.Curve() matches the
// expected curve themselves before calling Verify.
func (pf Proof) Verify(pkN, k *big.Int, ecdsaPub *crypto2.ECPoint) (bool, error) {
	// Input validation. Done synchronously up-front so malformed inputs cannot
	// reach GenerateXs (which dereferences k/ecdsaPub and would loop without a
	// sane pkN bit length).
	if pkN == nil || k == nil || ecdsaPub == nil || !ecdsaPub.ValidateBasic() {
		return false, nil
	}
	// k is hashed via k.Bytes() inside GenerateXs, which returns the
	// absolute value — distinct signed k inputs would alias to the same
	// xi. Reject negative k so the caller never produces ambiguous
	// transcripts.
	if k.Sign() < 0 {
		return false, nil
	}
	if pkN.Sign() != 1 || pkN.Bit(0) == 0 || pkN.BitLen() < verifyMinModulusBitLen {
		return false, nil
	}
	// Reject prime pkN. By Fermat's little theorem, x^p ≡ x (mod p) for every
	// x ∈ Z_p*, so a malicious prover with a prime modulus can set pf[i] = xi
	// (the verifier-derived challenge) and pass every iteration without ever
	// proving knowledge of a factorization. The trial-division goroutine below
	// only catches primes/composites with factors < verifyPrimesUntil; this
	// ProbablyPrime check closes the gap for larger primes.
	if pkN.ProbablyPrime(verifyPrimalityRounds) {
		return false, nil
	}
	iters := ProofIters
	for i := 0; i < iters; i++ {
		if pf[i] == nil {
			return false, nil
		}
		// pf[i] must be a canonical unit in Z_{pkN}*. The iteration check
		// pf[i]^pkN mod pkN otherwise has degenerate cases (pf[i]=0 makes
		// both sides 0 when xi happens to vanish; non-unit pf[i] leaks
		// gcd(pf[i], pkN) via the modexp).
		if pf[i].Sign() != 1 || pf[i].Cmp(pkN) != -1 {
			return false, nil
		}
		if new(big.Int).GCD(nil, nil, pf[i], pkN).Cmp(one) != 0 {
			return false, nil
		}
	}
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
	// Cut each candidate down to N's width before testing it against N, the way
	// modproof.sampleYModN does. A candidate is the concatenation of `blocks`
	// 256-bit hash blocks, so without the mask it is up to 256·⌈bits/256⌉ bits
	// wide while only candidates below N are accepted: the acceptance rate is
	// ≈ N/2^(256·blocks), i.e. ≈ 2^-(256 - bits mod 256) whenever bits is not a
	// multiple of 256, bottoming out at 2^-255 for bits ≡ 1. The loop below then
	// resamples, with a fresh counter each round, for longer than anyone will
	// wait — and its caller Verify is parked in a select waiting for the result.
	// Masked, the candidate is < 2^bits < 2N, so the acceptance rate is
	// φ(N)/2^bits > φ(N)/2N: a hair under 1/2 for the product of two large
	// primes this is used with, and never a cliff for anything else.
	//
	// The mask changes no challenge this library has ever produced: keygen and
	// resharing pin peer moduli to exactly paillierBitsLen = 2048 bits, and for
	// any bits ≡ 0 (mod 256) the concatenation is already exactly `bits` wide,
	// so AND-ing with 2^bits - 1 clears nothing. Verified byte for byte against
	// the pre-mask implementation for a 2048-bit modulus.
	mask := new(big.Int).Lsh(one, uint(bits))
	mask.Sub(mask, one)
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
		ret[i].And(ret[i], mask)
		if common.IsNumberInMultiplicativeGroup(N, ret[i]) {
			i++
		} else {
			n++
		}
	}
	return ret
}
