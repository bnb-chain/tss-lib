// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package safeparameter

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"golang.org/x/crypto/sha3"
)

const Iterations = 24

var (
	zero = big.NewInt(0)
	big4 = big.NewInt(4)
)

type Proof struct {
	Xis,
	Zis []*big.Int
	Ais,
	Bis []int
}

func GenOmega(NTilde *big.Int) *big.Int {
	var omega *big.Int
	for {
		omega = common.GetRandomPositiveInt(NTilde)
		jacobiSymbol := big.Jacobi(omega, NTilde)
		if jacobiSymbol == -1 {
			break
		}
	}

	return omega
}

func solve4root(x, phi, n *big.Int) *big.Int {
	var result big.Int
	e := big.NewInt(4)
	e.Add(phi, e)
	e.Mul(e, e)
	e.Rsh(e, 6)
	e.Mod(e, phi)
	return result.Exp(x, e, n)
}

func (pf *Proof) sanityCheck(challenge []*big.Int, omega *big.Int) bool {
	if omega == nil {
		return false
	}
	if len(challenge) != Iterations ||
		len(pf.Xis) != Iterations ||
		len(pf.Bis) != Iterations ||
		len(pf.Ais) != Iterations ||
		len(pf.Zis) != Iterations {
		return false
	}
	for i := 0; i < len(pf.Xis); i++ {
		if pf.Xis[i] == nil || pf.Zis[i] == nil {
			return false
		}
	}
	return true
}

func genYiPrime(yi, omega, NTildei, p, q *big.Int) (*big.Int, int, int) {
	check := func(yi *big.Int) bool {
		if big.Jacobi(yi, NTildei) == 1 && big.Jacobi(yi, p) == 1 && big.Jacobi(yi, q) == 1 {
			return true
		}
		return false
	}

	// b==0
	if check(yi) {
		return yi, 0, 0
	}
	// b==1
	yiOmega := new(big.Int).Mul(yi, omega)
	yiOmega = new(big.Int).Mod(yiOmega, NTildei)
	if check(yiOmega) {
		return yiOmega, 0, 1
	}

	// negyi:=new(big.Int).ModInverse(yi,NTildei)
	negyi := new(big.Int).Mod(new(big.Int).Sub(big.NewInt(0), yi), NTildei)
	if check(negyi) {
		return negyi, 1, 0
	}
	// negyiOmega:=new(big.Int).ModInverse(yiOmega,NTildei)
	negyiOmega := new(big.Int).Mod(new(big.Int).Sub(big.NewInt(0), yiOmega), NTildei)
	if check(negyiOmega) {
		return negyiOmega, 1, 1
	}
	return yi, 0, 0
}

func genXi(challenge []*big.Int, p, q, NTildei, phiN, omega *big.Int, ais, bis []int) ([]*big.Int, error) {
	xis := make([]*big.Int, Iterations)

	for i, yi := range challenge {
		if yi == nil {
			return nil, errors.New("invalid challenges")
		}
		yiPrime, a, b := genYiPrime(yi, omega, NTildei, p, q)
		xi := solve4root(yiPrime, phiN, NTildei)
		if new(big.Int).Exp(xi, big4, NTildei).Cmp(yiPrime) != 0 {
			return nil, errors.New("the yi is not in QR(n)")
		}
		xis[i] = xi
		ais[i] = a
		bis[i] = b
	}
	return xis, nil
}

func genZi(challenge []*big.Int, phiN, NTildei *big.Int) []*big.Int {
	var zis []*big.Int
	for _, yi := range challenge {
		N2 := new(big.Int).ModInverse(NTildei, phiN)
		zi := new(big.Int).Exp(yi, N2, NTildei)
		zis = append(zis, zi)
	}
	return zis
}

func ProvePaiBlumPreParams(challenges []*big.Int, omega *big.Int, params LocalPreParams) (*Proof, error) {
	if len(challenges) != Iterations || omega == nil {
		return nil, errors.New("the verifier send me the invalid parameter")
	}

	var yis []*big.Int
	for _, el := range challenges {
		yi := new(big.Int).Mod(el, params.NTildei)
		yis = append(yis, yi)
	}

	ais := make([]int, Iterations)
	bis := make([]int, Iterations)
	NTildei := params.NTildei
	xis, err := genXi(yis, params.BigP, params.BigQ, NTildei, params.PaillierSK.PhiN, omega, ais, bis)
	if err != nil {
		common.Logger.Errorf("fail to generate the xi with error %v", err)
		return nil, err
	}
	phiN := params.PaillierSK.PhiN
	zis := genZi(yis, phiN, NTildei)
	proof := Proof{
		Xis: xis,
		Zis: zis,
		Ais: ais,
		Bis: bis,
	}
	return &proof, nil
}

func verifyXis(xis, yis []*big.Int, ais, bis []int, NTildei, omega *big.Int) bool {
	var calXis []*big.Int
	var omegaYis []*big.Int
	for i := 0; i < len(xis); i++ {
		calXi := new(big.Int).Exp(xis[i], big4, NTildei)
		calXis = append(calXis, calXi)
	}

	for i := 0; i < len(yis); i++ {
		bi := bis[i]
		var wbi *big.Int
		if bi == 0 {
			wbi = big.NewInt(1)
		} else {
			wbi = omega
		}
		omegaYi := new(big.Int).Mul(wbi, yis[i])
		omegaYi = new(big.Int).Mod(omegaYi, NTildei)
		if ais[i] == 1 {
			omegaYi = new(big.Int).Mod(new(big.Int).Sub(big.NewInt(0), omegaYi), NTildei)
		}
		omegaYis = append(omegaYis, omegaYi)
	}
	for i := 0; i < len(xis); i++ {
		if calXis[i].Cmp(omegaYis[i]) != 0 {
			return false
		}
	}
	return true
}

func verifyZis(zis, yis []*big.Int, NTildei *big.Int) bool {
	var calculatedYis []*big.Int
	for _, zi := range zis {
		calculatedYi := zi.Exp(zi, NTildei, NTildei)
		calculatedYis = append(calculatedYis, calculatedYi)
	}
	for i := 0; i < len(yis); i++ {
		if yis[i].Cmp(calculatedYis[i]) != 0 {
			return false
		}
	}
	return true
}

func (pf *Proof) Verify(challenges []*big.Int, omega, NTildei *big.Int) bool {
	if !pf.sanityCheck(challenges, omega) {
		return false
	}
	var yis []*big.Int
	for _, el := range challenges {
		yi := new(big.Int).Mod(el, NTildei)
		yis = append(yis, yi)
	}
	zis := pf.Zis
	vXis := verifyXis(pf.Xis, yis, pf.Ais, pf.Bis, NTildei, omega)
	vZi := verifyZis(zis, yis, NTildei)
	return vXis && vZi
}

func GenChallenges(NTildei *big.Int, omegas []*big.Int) ([]*big.Int, error) {
	if NTildei == nil {
		return nil, errors.New("invalid input")
	}
	challengeBz := make([]byte, 32)
	var challenges []*big.Int
	hash := sha3.New256()
	for _, el := range omegas {
		_, err := hash.Write(el.Bytes())
		if err != nil {
			return nil, err
		}
	}
	omegaHAsh := hash.Sum(nil)
	cShakeHash := sha3.NewCShake256(NTildei.Bytes(), omegaHAsh)
	_, err := cShakeHash.Write(hash.Sum(NTildei.Bytes()))
	if err != nil {
		return nil, err
	}

	for i := 0; i < Iterations; i++ {
		cShakeHash.Read(challengeBz)
		challenges = append(challenges, new(big.Int).SetBytes(challengeBz))
	}
	return challenges, nil
}
