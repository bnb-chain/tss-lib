// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package safeparameter

import (
	"errors"
	"math/big"
	"runtime"
	"time"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
)

type LocalPreParams struct {
	PaillierSK *paillier.PrivateKey // ski
	NTildei,
	H1i, H2i,
	Alpha, Beta,
	P, Q *big.Int
	BigP, BigQ *big.Int
}

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	paillierModulusLen = 2048
	// Two 1024-bit safe primes to produce NTilde
	safePrimeBitLen = 1024
	// Ticker for printing log statements while generating primes/modulus
	logProgressTickInterval = 8 * time.Second
)

var one = big.NewInt(1)

// GeneratePreParams finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
func GeneratePreParams(timeout time.Duration, optionalConcurrency ...int) (*LocalPreParams, error) {
	var concurrency int
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			panic(errors.New("GeneratePreParams: expected 0 or 1 item in `optionalConcurrency`"))
		}
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.NumCPU()
	}
	if concurrency /= 3; concurrency < 1 {
		concurrency = 1
	}

	// prepare for concurrent Paillier and safe prime generation
	paiCh := make(chan *paillier.PrivateKey, 1)
	sgpCh := make(chan []*common.GermainSafePrime, 1)

	// 4. generate Paillier public key E_i, private key and proof
	go func(ch chan<- *paillier.PrivateKey) {
		common.Logger.Info("generating the Paillier modulus, please wait...")
		start := time.Now()
		// more concurrency weight is assigned here because the paillier primes have a requirement of having "large" P-Q
		PiPaillierSk, _, err := paillier.GenerateKeyPair(paillierModulusLen, timeout, concurrency*2)
		if err != nil {
			ch <- nil
			return
		}
		common.Logger.Infof("paillier modulus generated. took %s\n", time.Since(start))
		ch <- PiPaillierSk
	}(paiCh)

	// 5-7. generate safe primes for ZKPs used later on
	go func(ch chan<- []*common.GermainSafePrime) {
		var err error
		common.Logger.Info("generating the safe primes for the signing proofs, please wait...")
		start := time.Now()
		sgps, err := common.GetRandomSafePrimesConcurrent(safePrimeBitLen, 2, timeout, concurrency)
		if err != nil {
			ch <- nil
			return
		}
		common.Logger.Infof("safe primes generated. took %s\n", time.Since(start))
		ch <- sgps
	}(sgpCh)

	// this ticker will print a log statement while the generating is still in progress
	logProgressTicker := time.NewTicker(logProgressTickInterval)

	// errors can be thrown in the following code; consume chans to end goroutines here
	var sgps []*common.GermainSafePrime
	var paiSK *paillier.PrivateKey
consumer:
	for {
		select {
		case <-logProgressTicker.C:
			common.Logger.Info("still generating primes...")
		case sgps = <-sgpCh:
			if sgps == nil ||
				sgps[0] == nil || sgps[1] == nil ||
				!sgps[0].Prime().ProbablyPrime(30) || !sgps[1].Prime().ProbablyPrime(30) ||
				!sgps[0].SafePrime().ProbablyPrime(30) || !sgps[1].SafePrime().ProbablyPrime(30) {
				return nil, errors.New("timeout or error while generating the safe primes")
			}
			if paiSK != nil {
				break consumer
			}
		case paiSK = <-paiCh:
			if paiSK == nil {
				return nil, errors.New("timeout or error while generating the Paillier secret key")
			}
			if sgps != nil {
				break consumer
			}
		}
	}
	logProgressTicker.Stop()

	P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
	NTildei := new(big.Int).Mul(P, Q)
	modNTildeI := common.ModInt(NTildei)

	p, q := sgps[0].Prime(), sgps[1].Prime()
	modPQ := common.ModInt(new(big.Int).Mul(p, q))
	f1 := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
	alpha := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
	beta := modPQ.Inverse(alpha)
	h1i := modNTildeI.Mul(f1, f1)
	h2i := modNTildeI.Exp(h1i, alpha)

	preParams := &LocalPreParams{
		PaillierSK: paiSK,
		NTildei:    NTildei,
		H1i:        h1i,
		H2i:        h2i,
		Alpha:      alpha,
		Beta:       beta,
		P:          p,
		Q:          q,
	}
	return preParams, nil
}

func generateSuitableParameter(timeout time.Duration, concurrency int, sgpsChan chan []*common.GermainSafePrime) error {
	for {
		sgps, err := common.GetRandomSafePrimesConcurrent(safePrimeBitLen, 2, timeout, concurrency)
		if err != nil {
			sgpsChan <- nil
			return err
		}
		// P,Q not necessary to be the safe prime
		P := sgps[0].SafePrime()
		Q := sgps[1].SafePrime()
		if sgps[0] == nil || sgps[1] == nil ||
			!P.ProbablyPrime(30) || !Q.ProbablyPrime(30) || new(big.Int).Sub(P, Q).BitLen() < (paillierModulusLen/2)-paillier.PQBitLenDifference {
			common.Logger.Infof("the safe prime fails the check, we continue to search for prime number\n")
			continue
		}

		// we check whether p,q =3mod4 described in CGGMP section 2.2.1 paper
		rp := new(big.Int).Mod(P, big.NewInt(4))
		rq := new(big.Int).Mod(Q, big.NewInt(4))

		if rp.Cmp(big.NewInt(3)) != 0 || rq.Cmp(big.NewInt(3)) != 0 {
			common.Logger.Info("fail the blum prime check, continue searching")
			continue
		}

		N := new(big.Int).Mul(P, Q)
		if N.Bit(0) == 0 {
			common.Logger.Info("N is not odd, continue searching")
			continue
		}
		PMinus1, QMinus1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
		// phiN = P-1 * Q-1
		phiN := new(big.Int).Mul(PMinus1, QMinus1)
		// we check gcd(N, phiN) described in CGGMP section 2.2.1 paper
		if new(big.Int).GCD(nil, nil, N, phiN).Cmp(one) == 0 {
			sgpsChan <- sgps
			return nil
		}
		common.Logger.Info("fail the gcd(N,PhiN)==1 check, continue searching..")
	}
}

func generateLocalPaillierBlumeParameter(sgps []*common.GermainSafePrime) (*LocalPreParams, error) {
	if sgps == nil {
		return nil, errors.New("invalid safe parameter")
	}
	P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
	p, q := sgps[0].Prime(), sgps[1].Prime()
	PMinus1, QMinus1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
	N := new(big.Int).Mul(P, Q)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)
	pk := paillier.PublicKey{N: N}
	paiSK := paillier.PrivateKey{
		PublicKey: pk,
		LambdaN:   lambdaN,
		PhiN:      phiN,
	}
	// we use the same N for h1,h2 proof
	NTildei := new(big.Int).Set(N)
	modNTildeI := common.ModInt(N)

	modPQ := common.ModInt(new(big.Int).Mul(p, q))
	f1 := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
	alpha := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
	beta := modPQ.Inverse(alpha)
	h1i := modNTildeI.Mul(f1, f1)
	h2i := modNTildeI.Exp(h1i, alpha)

	preParams := &LocalPreParams{
		PaillierSK: &paiSK,
		NTildei:    NTildei,
		H1i:        h1i,
		H2i:        h2i,
		Alpha:      alpha,
		Beta:       beta,
		P:          p,
		Q:          q,
		BigP:       P,
		BigQ:       Q,
	}
	return preParams, nil
}

// GeneratePreParams finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
func GeneratePaiBlumPreParams(timeout time.Duration, optionalConcurrency ...int) (*LocalPreParams, error) {
	var concurrency int
	var preParams *LocalPreParams
	var err error
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			panic(errors.New("GeneratePreParams: expected 0 or 1 item in `optionalConcurrency`"))
		}
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.NumCPU()
	}
	if concurrency /= 3; concurrency < 1 {
		concurrency = 1
	}
	// this ticker will print a log statement while the generating is still in progress
	logProgressTicker := time.NewTicker(logProgressTickInterval)

	sgpsChan := make(chan []*common.GermainSafePrime)

	start := time.Now()
	defer func() {
		common.Logger.Infof("safe primes generated. took %s\n", time.Since(start))
	}()

	go func() {
		err := generateSuitableParameter(timeout, concurrency, sgpsChan)
		if err != nil {
			common.Logger.Error("fail to generate the safe parameter")
		}
	}()

	for {
		select {
		case <-logProgressTicker.C:
			common.Logger.Info("still generating primes...")
		case sgps := <-sgpsChan:
			preParams, err = generateLocalPaillierBlumeParameter(sgps)
			if err == nil {
				return preParams, nil
			}

		}
	}
}

func (preParams LocalPreParams) Validate() bool {
	return preParams.PaillierSK != nil &&
		preParams.NTildei != nil &&
		preParams.H1i != nil &&
		preParams.H2i != nil
}

func (preParams LocalPreParams) ValidateWithProof() bool {
	return preParams.Validate() &&
		preParams.Alpha != nil &&
		preParams.Beta != nil &&
		preParams.P != nil &&
		preParams.Q != nil
}
