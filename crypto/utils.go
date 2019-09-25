package crypto

import (
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
)

func GenerateNTildei(rsaPrimes [2]*big.Int) (NTildei, h1i, h2i *big.Int, err error) {
	if rsaPrimes[0] == nil || rsaPrimes[1] == nil {
		return nil, nil, nil, fmt.Errorf("GenerateNTildei: needs two primes, got %v", rsaPrimes)
	}
	NTildei = new(big.Int).Mul(rsaPrimes[0], rsaPrimes[1])
	h1 := common.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	h2 := common.GetRandomGeneratorOfTheQuadraticResidue(NTildei)
	return NTildei, h1, h2, nil
}
