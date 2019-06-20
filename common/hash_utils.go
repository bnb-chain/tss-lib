package common

import (
	"math/big"
)

var (
	zero = big.NewInt(0)
)

// RejectionSample implements the rejection sample logic in GG18Spec (6) Fig. 12.
// An error may be thrown if writing to the SHA512/256 hash fails.
func RejectionSample(q *big.Int, eHash *big.Int) *big.Int { // e' = eHash
	qBits := q.BitLen()
	// e = the first |q| bits of e'
	e := firstBitsOf(qBits, eHash)
	// while e is not between 0-q
	for !(e.Cmp(q) == -1 && zero.Cmp(q) == -1) {
		eHash := SHA512_256i(eHash)
		e = firstBitsOf(qBits, eHash)
	}
	return e
}

func firstBitsOf(bits int, v *big.Int) *big.Int {
	e := new(big.Int)
	for i := 0; i < bits; i++ {
		bit := v.Bit(i)
		e = e.SetBit(e, i, bit)
	}
	return e
}
