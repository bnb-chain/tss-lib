// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package dlnp

import (
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
)
const(
	SmqP="83080484992051001072653397990246162727815239902277527669190236469277678405916008568843132984074506771344634913806825906632125834929247226856161903356119728958826709672580836941349409606255226373189873854932024872646532842534014551107609876960812129171596090897872060818176919861898553926147184589319693828559"
	P="166160969984102002145306795980492325455630479804555055338380472938555356811832017137686265968149013542689269827613651813264251669858494453712323806712239457917653419345161673882698819212510452746379747709864049745293065685068029102215219753921624258343192181795744121636353839723797107852294369178639387657119"
	Q="158056135542341484152552106702684858696480642896426923299153758911827496125977147172482598717581755197781935363099588810462692446144561524687542944179004988720887088513392459351212041600788911808485964220588568916339869497909522183398204688697136128648925914382115161879872143680581234492528917963769538756283"
	SmqQ="79028067771170742076276053351342429348240321448213461649576879455913748062988573586241299358790877598890967681549794405231346223072280762343771472089502494360443544256696229675606020800394455904242982110294284458169934748954761091699102344348568064324462957191057580939936071840290617246264458981884769378141"
)

type proofInput struct {
	h1,
	h2,
	alpha,
	p,
	q,
	n *big.Int
}

func genh1h2()(*proofInput,error){
	P,ok1:=new(big.Int).SetString(P,10)
	Q,ok2:=new(big.Int).SetString(Q,10)
	p,ok3:=new(big.Int).SetString(SmqP,10)
	q,ok4:=new(big.Int).SetString(SmqQ,10)
	if !ok1||!ok2||!ok3||!ok4{
		return nil,errors.New("fail to load the parameter")
	}

	N := new(big.Int).Mul(P, Q)
	modNTildeI := common.ModInt(N)

	f1 := common.GetRandomPositiveRelativelyPrimeInt(N)
	alpha := common.GetRandomPositiveRelativelyPrimeInt(N)
	h1 := modNTildeI.Mul(f1, f1)
	h2 := modNTildeI.Exp(h1, alpha)
	proofInput:=proofInput{
		h1,
		h2,
		alpha,
		p,
		q,
		N,
	}
	return &proofInput,nil
}


func TestNewProofPass(t *testing.T) {
	input,err:=genh1h2()
	assert.Nil(t, err)
	proof, err:=NewProof(input.h1, input.h2, input.alpha, input.p, input.q, input.n)
	assert.Nil(t, err)
	ret:=proof.Verify(input.h1,input.h2,input.n)
	assert.True(t, ret)
}
func TestNewProofFail(t *testing.T) {
	input,err:=genh1h2()
	assert.Nil(t, err)
	// 1. test h1,h2,p,q,x >= n
	_, err=NewProof(input.n, input.h2, input.alpha, input.p, input.q, input.n)
	assert.NotNil(t, err)
	_, err=NewProof(input.h1, input.n, input.alpha, input.p, input.q, input.n)
	assert.NotNil(t, err)
	_, err=NewProof(input.h1, input.h2, input.n, input.p, input.q, input.n)
	assert.NotNil(t, err)
	_, err=NewProof(input.h1, input.h2, input.alpha, input.n, input.q, input.n)
	assert.NotNil(t, err)
	_, err=NewProof(input.h1, input.h2, input.alpha, input.p, input.n, input.n)
	assert.NotNil(t, err)

	// 2. test the invalid proof
	proof, err:=NewProof(input.h1, input.h2, input.alpha, input.p, input.n, input.n)
	assert.NotNil(t, err)
	ret:=proof.Verify(input.h1,input.h1,input.n)
	assert.False(t, ret)

	// 3. test h2 !=xh1
	h2 := new(big.Int).Sub(input.h2,big.NewInt(1))
	proof, err=NewProof(input.h1, h2, input.alpha, input.p, input.n, input.n)
	assert.NotNil(t, err)
	ret=proof.Verify(input.h1,h2,input.n)
	assert.False(t, ret)
}
