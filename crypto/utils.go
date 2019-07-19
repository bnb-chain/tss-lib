package crypto

import (
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common/random"
)

func GenerateNTildei(rsaPrimes []*big.Int) (NTildei, h1i, h2i *big.Int, err error) {
	if len(rsaPrimes) < 2 {
		return nil, nil, nil, fmt.Errorf("GenerateNTildei: needs two primes, got %d", len(rsaPrimes))
	}
	NTildei = new(big.Int).Mul(rsaPrimes[0], rsaPrimes[1])
	h1 := random.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	h2 := random.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	return NTildei, h1, h2, nil
}
