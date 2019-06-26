package mta

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

func AliceInit(pkA *paillier.PublicKey, a, _, _, _ *big.Int) (*big.Int, error) {
	// TODO: add call to ProveRangeAlice, return proof `piA`
	cA, _, err := pkA.EncryptAndReturnRandomness(a)
	if err != nil {
		return nil, err
	}
	return cA, nil
}

func BobMid(pkA *paillier.PublicKey, b, cA, _, _, _, _, _, _ *big.Int) (beta *big.Int, cB *big.Int, piB *big.Int, beta1 *big.Int, err error) {
	q := tss.EC().Params().N
	beta1 = random.GetRandomPositiveInt(pkA.N)
	// TODO: add call to ProveMta_Bob, return proof `piB`
	cBeta1, _, err := pkA.EncryptAndReturnRandomness(beta1)
	cB1, err := pkA.HomoMult(b, cA)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cB2, err := pkA.HomoAdd(cB1, cBeta1)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	beta = new(big.Int).Mod(new(big.Int).Sub(zero, beta1), q)
	return beta, cB2, nil, beta1, nil
}

func AliceEnd(pkA *paillier.PublicKey, _, _, _, _, cB, _ *big.Int, sk *paillier.PrivateKey) (*big.Int, error) {
	alpha, err := sk.Decrypt(cB)
	if err != nil {
		return nil, err
	}
	q := tss.EC().Params().N
	return new(big.Int).Mod(alpha, q), nil
}
