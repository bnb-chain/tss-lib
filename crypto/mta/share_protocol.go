package mta

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

func AliceInit(pkA *paillier.PublicKey, a, _, _, _ *big.Int) (*big.Int, error) {
	// TODO: add call to ProveRangeAlice, return proof `piA`
	c, _, err := pkA.EncryptAndReturnRandomness(a)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func BobMid(pkA *paillier.PublicKey, b, cA, _, _, _, _, _, _ *big.Int) (*big.Int, error) {
	q := tss.EC().Params().N
	betaRnd := random.GetRandomPositiveInt(pkA.N)
	// TODO: add call to ProveMta_Bob, return proof `piB`
	cTmp, _, err := pkA.EncryptAndReturnRandomness(betaRnd)
	cB, err := pkA.HomoMult(b, cA)
	if err != nil {
		return nil, err
	}
	cB, err = pkA.HomoAdd(cB, cTmp)
	if err != nil {
		return nil, err
	}
	beta := new(big.Int).Mod(new(big.Int).Sub(zero, betaRnd), q)
	return beta, nil
}

func AliceEnd(pkA *paillier.PublicKey, _, _, _, _, cB *big.Int, sk *paillier.PrivateKey) (*big.Int, error) {
	alpha, err := sk.Decrypt(cB)
	if err != nil {
		return nil, err
	}
	q := tss.EC().Params().N
	return new(big.Int).Mod(alpha, q), nil
}
