package keygen

import (
	"fmt"
	"math/big"

	"golang.org/x/crypto/sha3"
)

const (
	// h1, h2 for range proofs constant string (GG18 Fig. 13)
	H1H2SHA256Constant = "%d-03jan2009ChancelloronBrinkofSecondBailoutforBanks:)"
)

// Generate h1, h2 for range proofs (GG18 Fig. 13)
func generateH1H2ForRangeProofs() (H1, H2 *big.Int) {
	// generate h1, h2 for range proofs (GG18 Fig. 13)
	sha3256 := sha3.New256()
	h1 := make([]byte, 0, 32 * 8) // 8x SHA256
	h2 := make([]byte, 0, 32 * 8)
	for i := 1; i <= 16; i++ {
		str := []byte(fmt.Sprintf(H1H2SHA256Constant, i))
		sha3256.Write(str)
		digest := sha3256.Sum(nil)
		if i <= 8 {
			h1 = append(h1, digest...)
		} else {
			h2 = append(h2, digest...)
		}
	}
	return new(big.Int).SetBytes(h1), new(big.Int).SetBytes(h2)
}
