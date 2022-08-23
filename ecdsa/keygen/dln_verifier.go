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
)

type DlnProofVerifier struct {
	semaphore chan interface{}
}

func NewDlnProofVerifier(optionalConcurrency ...int) *DlnProofVerifier {
	var concurrency int
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			panic(errors.New("NewDlnProofVerifier: expected 0 or 1 item in `optionalConcurrency`"))
		}
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.NumCPU()
	}

	semaphore := make(chan interface{}, concurrency)

	return &DlnProofVerifier{
		semaphore: semaphore,
	}
}

func (dpv *DlnProofVerifier) VerifyDLNProof1(
	r1msg *KGRound1Message,
	h1, h2, n *big.Int,
	onDone func(bool),
) {
	dpv.semaphore <- struct{}{}
	go func() {
		defer func() { <-dpv.semaphore }()

		dlnProof, err := r1msg.UnmarshalDLNProof1()
		if err != nil {
			onDone(false)
			return
		}

		onDone(dlnProof.Verify(h1, h2, n))
	}()
}

func (dpv *DlnProofVerifier) VerifyDLNProof2(
	r1msg *KGRound1Message,
	h1, h2, n *big.Int,
	onDone func(bool),
) {
	dpv.semaphore <- struct{}{}
	go func() {
		defer func() { <-dpv.semaphore }()

		dlnProof, err := r1msg.UnmarshalDLNProof2()
		if err != nil {
			onDone(false)
			return
		}

		onDone(dlnProof.Verify(h1, h2, n))
	}()
}