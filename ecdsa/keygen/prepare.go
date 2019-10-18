// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"
	"runtime"
	"time"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
)

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	paillierModulusLen = 2048
	// Two 1024-bit safe primes to produce NTilde
	safePrimeBitLen = 1024
)

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

	// prepare for concurrent Paillier and safe prime generation
	paiCh := make(chan *paillier.PrivateKey)
	sgpCh := make(chan []*common.GermainSafePrime)

	// 4. generate Paillier public key E_i, private key and proof
	go func(ch chan<- *paillier.PrivateKey) {
		start := time.Now()
		PiPaillierSk, _ := paillier.GenerateKeyPair(paillierModulusLen, timeout, concurrency/2) // sk contains pk
		common.Logger.Debugf("paillier keygen done. took %s\n", time.Since(start))
		ch <- PiPaillierSk
	}(paiCh)

	// 5-7. generate safe primes for ZKPs used later on
	go func(ch chan<- []*common.GermainSafePrime) {
		var err error
		start := time.Now()
		sgps, err := common.GetRandomSafePrimesConcurrent(safePrimeBitLen, 2, timeout, concurrency/2)
		if err != nil {
			ch <- nil
			return
		}
		common.Logger.Debugf("safe primes generated. took %s\n", time.Since(start))
		ch <- sgps
	}(sgpCh)

	// errors can be thrown in the following code; consume chans to end goroutines here
	sgps, paiSK := <-sgpCh, <-paiCh
	if sgps == nil || sgps[0] == nil || sgps[1] == nil || !sgps[0].Validate() || !sgps[1].Validate() {
		return nil, errors.New("timeout or error while generating the 2 safe primes")
	}

	NTildei, h1i, h2i, err := crypto.GenerateNTildei([2]*big.Int{sgps[0].SafePrime(), sgps[1].SafePrime()})
	if err != nil {
		return nil, err
	}

	preParams := &LocalPreParams{
		PaillierSK: paiSK,
		NTildei:    NTildei,
		H1i:        h1i,
		H2i:        h2i,
	}
	return preParams, nil
}
