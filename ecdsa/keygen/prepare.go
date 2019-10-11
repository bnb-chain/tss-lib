// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"
	"runtime"
	"time"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
)

func GeneratePreParams() (*LocalPreParams, error) {
	// prepare for concurrent Paillier and safe prime generation
	paiCh := make(chan *paillier.PrivateKey)
	sgpCh := make(chan []*common.SophieGermainPrime)

	// 4. generate Paillier public key "Ei", private key and proof
	go func(ch chan<- *paillier.PrivateKey) {
		start := time.Now()
		PiPaillierSk, _ := paillier.GenerateKeyPair(PaillierModulusLen) // sk contains pk
		common.Logger.Debugf("paillier keygen done. took %s\n", time.Since(start))
		ch <- PiPaillierSk
	}(paiCh)

	// 5-7. generate safe primes for ZKPs used later on
	go func(ch chan<- []*common.SophieGermainPrime) {
		start := time.Now()
		sgps := common.GetRandomSophieGermainPrimesConcurrent(SafePrimeBitLen, 2, runtime.NumCPU())
		common.Logger.Debugf("safe primes generated. took %s\n", time.Since(start))
		ch <- sgps
	}(sgpCh)

	// errors can be thrown in the following code; consume chans to end goroutines here
	sgps, paiSK := <-sgpCh, <-paiCh

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
