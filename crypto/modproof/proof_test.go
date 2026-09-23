// Copyright © 2019-2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package modproof_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v4/common"
	. "github.com/bnb-chain/tss-lib/v4/crypto/modproof"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/stretchr/testify/assert"
)

var Session = []byte("session")

func TestMod(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N

	proof, err := NewProof(Session, N, P, Q, rand.Reader)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])
	assert.NoError(test, err)

	ok := proof.Verify(Session, N)
	assert.True(test, ok, "proof must verify")
}

func TestModCT(test *testing.T) {
	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()

	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N

	proof, err := NewProof(Session, N, P, Q, rand.Reader)
	assert.NoError(test, err)

	proofBzs := proof.Bytes()
	proof, err = NewProofFromBytes(proofBzs[:])
	assert.NoError(test, err)

	ok := proof.Verify(Session, N)
	assert.True(test, ok, "CT proof must verify")
}

var (
	one = big.NewInt(1)
)

func NewHackedProof(Session []byte, N, P *big.Int, Q []*big.Int) (*ProofMod, error) {
	Phi := new(big.Int).Sub(P, one)
	bigQ := new(big.Int).Set(one)
	for _, q := range Q {
		Phi.Mul(Phi, new(big.Int).Sub(q, one))
		bigQ.Mul(bigQ, q)
	}
	invBigQ := new(big.Int).ModInverse(bigQ, P)
	// Now W = 1 mod bigP and W = 0 mod bigQ
	W := new(big.Int).Mul(invBigQ, bigQ)
	// Verify W ≡ 1 (mod P)
	if new(big.Int).Mod(W, P).Cmp(one) != 0 {
		return nil, fmt.Errorf("w is not congruent to 1 modulo p")
	}
	// Verify W ≡ 0 (mod q) for all q in Q
	for _, q := range Q {
		if new(big.Int).Mod(W, q).Cmp(big.NewInt(0)) != 0 {
			return nil, fmt.Errorf("w is not congruent to 0 modulo all values in q")
		}
	}
	// Fig 16.2 - Computing the Y values
	Y := [Iterations]*big.Int{}
	for i := range Y {
		ei := common.SHA512_256i_TAGGED(Session, append([]*big.Int{W, N},
			Y[:i]...)...)
		Y[i] = common.RejectionSample(N, ei)
	}
	// Fig 16.3
	modN, modP := common.ModInt(N), common.ModInt(P)
	// modPhi := common.ModInt(Phi)
	invN := new(big.Int).ModInverse(N, Phi)
	X := [Iterations]*big.Int{}
	// Fix bitLen of A and B
	A := new(big.Int).Lsh(one, Iterations)
	B := new(big.Int).Lsh(one, Iterations)
	Z := [Iterations]*big.Int{}
	// for fourth-root mod p
	expo := new(big.Int).Add(P, one)
	expo = new(big.Int).Rsh(expo, 3)
	for i := range Y {
		B.SetBit(B, i, uint(1))
		Yi := new(big.Int).SetBytes(Y[i].Bytes())
		if big.Jacobi(Yi, P) == 1 {
			A.SetBit(A, i, uint(0))
		} else {
			A.SetBit(A, i, uint(1))
			Yi = modN.Mul(big.NewInt(-1), Yi)
		}
		Xi := modN.Mul(modP.Exp(Yi, expo), W)
		Zi := modN.Exp(Y[i], invN)
		X[i], Z[i] = Xi, Zi
	}
	pf := &ProofMod{W: W, X: X, A: A, B: B, Z: Z}
	return pf, nil
}

func mustSetString(s string) *big.Int {
	i, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("Failed to parse integer: " + s)
	}
	return i
}

func TestVerifyRejectsMalformedN(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)
	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N
	proof, err := NewProof(Session, N, P, Q, rand.Reader)
	assert.NoError(test, err)

	test.Run("nil N", func(t *testing.T) {
		assert.False(t, proof.Verify(Session, nil))
	})
	test.Run("zero N", func(t *testing.T) {
		assert.False(t, proof.Verify(Session, big.NewInt(0)))
	})
	test.Run("negative N", func(t *testing.T) {
		assert.False(t, proof.Verify(Session, big.NewInt(-1)))
	})
	test.Run("even N", func(t *testing.T) {
		even := new(big.Int).Lsh(N, 1)
		assert.False(t, proof.Verify(Session, even))
	})
	test.Run("too small N", func(t *testing.T) {
		small := big.NewInt(15) // 3*5: composite, odd, but only 4 bits
		assert.False(t, proof.Verify(Session, small))
	})
	test.Run("prime N", func(t *testing.T) {
		// A 2048-bit prime: passes bit-length and oddness, must be rejected
		// by the ProbablyPrime check before the proof structure is examined.
		primeN := common.GetRandomPrimeInt(rand.Reader, 2048)
		assert.False(t, proof.Verify(Session, primeN))
	})
}

func TestVerifyRejectsNonUnitZX(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)
	P, Q, N := preParams.PaillierSK.P, preParams.PaillierSK.Q, preParams.PaillierSK.N
	proof, err := NewProof(Session, N, P, Q, rand.Reader)
	assert.NoError(test, err)

	test.Run("Z[0] non-unit (factor of N)", func(t *testing.T) {
		bad := *proof
		bad.Z[0] = new(big.Int).Set(P)
		assert.False(t, bad.Verify(Session, N))
	})
	test.Run("X[0] non-unit (factor of N)", func(t *testing.T) {
		bad := *proof
		bad.X[0] = new(big.Int).Set(Q)
		assert.False(t, bad.Verify(Session, N))
	})
}

func TestAttackMod(test *testing.T) {
	fmt.Printf("Starting TestAttackMod\n")

	// need p % 8 = 7
	P := mustSetString("11956161572522965463")
	fmt.Printf("P = %v\n", P)

	Q := []*big.Int{
		mustSetString("2495927741"),
		mustSetString("3726287311"),
		mustSetString("3756248813"),
		mustSetString("3962607427"),
		mustSetString("2685519289"),
		mustSetString("2316427879"),
		mustSetString("3704490329"),
	}
	fmt.Printf("Q = %v\n", Q)

	N := new(big.Int).SetBytes(P.Bytes())
	for _, q := range Q {
		N.Mul(N, q)
	}
	proof, err := NewHackedProof(Session, N, P, Q)
	assert.NoError(test, err)
	ok := proof.Verify(Session, N)
	assert.Falsef(test, ok, "false proof should not verify")
}

// NewProof samples its W from GetRandomQuadraticNonResidue, which has nothing
// to return when N is a perfect square: Jacobi(w, m²) = Jacobi(w, m)² is never
// -1, so the sampler's acceptance probability is exactly zero. NewProof is
// called from keygen round 2 while the party mutex is held, so it has to come
// back with an error rather than park there.
func TestNewProofRejectsAModulusItCannotSampleFor(test *testing.T) {
	// m², for m the first prime above 3·2^1022: an odd, composite, 2048-bit
	// modulus that clears every check Verify makes. P·Q = N holds too, so the
	// only thing wrong with it is the shape of N.
	m, ok := new(big.Int).SetString("c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013f7", 16)
	assert.True(test, ok)
	N := new(big.Int).Mul(m, m)
	assert.Equal(test, 2048, N.BitLen())

	type result struct {
		proof *ProofMod
		err   error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				test.Errorf("NewProof panicked: %v", r)
				done <- result{}
			}
		}()
		proof, err := NewProof(Session, N, m, m, rand.Reader)
		done <- result{proof, err}
	}()
	// The goroutine is abandoned on timeout rather than joined: before the fix
	// it spins in the sampler and would hang `go test` itself.
	select {
	case got := <-done:
		assert.Error(test, got.err, "must reject a modulus it cannot sample a non-residue for")
		assert.Nil(test, got.proof)
	case <-time.After(20 * time.Second):
		test.Fatal("NewProof must return rather than sample forever")
	}
}
