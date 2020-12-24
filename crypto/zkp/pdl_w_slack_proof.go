// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// go port of https://github.com/KZen-networks/multi-party-ecdsa/blob/fd3607b07a3327e0cb8ad053255ae1013e0ca18b/src/utilities/zk_pdl_with_slack/mod.rs

package zkp

import (
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmts "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

type (
	PDLwSlackStatement struct {
		CipherText     *big.Int
		PK             *paillier.PublicKey
		Q, G           *crypto.ECPoint
		H1, H2, NTilde *big.Int
	}

	PDLwSlackWitness struct {
		X, R *big.Int
		SK   *paillier.PrivateKey
	}

	PDLwSlackProof struct {
		Z  *big.Int
		U1 *crypto.ECPoint
		U2, U3,
		S1, S2, S3 *big.Int
	}
)

const (
	PDLwSlackMarshalledParts = 11
)

var (
	one = big.NewInt(1)
)

func NewPDLwSlackProof(wit PDLwSlackWitness, st PDLwSlackStatement) PDLwSlackProof {
	q := tss.EC().Params().N
	q3 := new(big.Int).Mul(q, q)
	q3.Mul(q3, q)
	qNTilde := new(big.Int).Mul(q, st.NTilde)
	q3NTilde := new(big.Int).Mul(q3, st.NTilde)

	alpha := common.GetRandomPositiveInt(q3)
	nSubOne := new(big.Int).Add(st.PK.N, one)
	beta := new(big.Int).Add(one, common.GetRandomPositiveInt(nSubOne))
	rho := common.GetRandomPositiveInt(qNTilde)
	gamma := common.GetRandomPositiveInt(q3NTilde)

	z := commitmentUnknownOrder(st.H1, st.H2, st.NTilde, wit.X, rho)
	u1 := st.G.ScalarMult(alpha)
	nOne := new(big.Int).Add(st.PK.N, one)
	u2 := commitmentUnknownOrder(nOne, beta, st.PK.NSquare(), alpha, st.PK.N)
	u3 := commitmentUnknownOrder(st.H1, st.H2, st.NTilde, alpha, gamma)

	e := common.SHA512_256i(st.G.X(), st.G.Y(), st.Q.X(), st.Q.Y(), st.CipherText, z, u1.X(), u1.Y(), u2, u3)
	s1 := new(big.Int).Mul(e, wit.X)
	s3 := new(big.Int).Mul(e, rho)
	s1.Add(s1, alpha)
	s2 := commitmentUnknownOrder(wit.R, beta, st.PK.N, e, one)
	s3.Add(s3, gamma)

	return PDLwSlackProof{z, u1, u2, u3, s1, s2, s3}
}

func (pf PDLwSlackProof) Verify(st PDLwSlackStatement) bool {
	q := tss.EC().Params().N

	e := common.SHA512_256i(st.G.X(), st.G.Y(), st.Q.X(), st.Q.Y(), st.CipherText, pf.Z, pf.U1.X(), pf.U1.Y(), pf.U2, pf.U3)
	gS1 := st.G.ScalarMult(pf.S1)
	eFeNeg := new(big.Int).Sub(q, e)
	yMinusE := st.Q.ScalarMult(eFeNeg)
	u1Test, err := gS1.Add(yMinusE)
	if err != nil {
		return false
	}

	nOne, eNeg := new(big.Int).Add(st.PK.N, one), new(big.Int).Neg(e)
	u2TestTmp := commitmentUnknownOrder(nOne, pf.S2, st.PK.NSquare(), pf.S1, st.PK.N)
	u2Test := commitmentUnknownOrder(u2TestTmp, st.CipherText, st.PK.NSquare(), one, eNeg)
	u3TestTmp := commitmentUnknownOrder(st.H1, st.H2, st.NTilde, pf.S1, pf.S3)
	u3Test := commitmentUnknownOrder(u3TestTmp, pf.Z, st.NTilde, one, eNeg)

	return pf.U1.Equals(u1Test) &&
		pf.U2.Cmp(u2Test) == 0 &&
		pf.U3.Cmp(u3Test) == 0
}

func (pf PDLwSlackProof) Marshal() ([][]byte, error) {
	cb := cmts.NewBuilder()
	cb = cb.AddPart(pf.Z)
	cb = cb.AddPart(pf.U1.X(), pf.U1.Y(), pf.U2, pf.U3)
	cb = cb.AddPart(pf.S1, pf.S2, pf.S3)
	ints, err := cb.Secrets()
	if err != nil {
		return nil, err
	}
	bzs := make([][]byte, len(ints))
	for i, part := range ints {
		if part == nil {
			bzs[i] = []byte{}
			continue
		}
		bzs[i] = part.Bytes()
	}
	return bzs, nil
}

func UnmarshalPDLwSlackProof(bzs [][]byte) (*PDLwSlackProof, error) {
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}
	parsed, err := cmts.ParseSecrets(bis)
	if err != nil {
		return nil, err
	}
	expParts := 3
	if len(parsed) != expParts {
		return nil, fmt.Errorf("UnmarshalPDLwSlackProof expected %d parts but got %d", expParts, len(parsed))
	}
	if len1 := len(parsed[0]); len1 != 1 {
		return nil, fmt.Errorf("UnmarshalPDLwSlackProof, part 1, expected len %d but copied %d", 1, len1)
	}
	if len2 := len(parsed[1]); len2 != 4 {
		return nil, fmt.Errorf("UnmarshalPDLwSlackProof, part 2, expected len %d but copied %d", 4, len2)
	}
	if len3 := len(parsed[2]); len3 != 3 {
		return nil, fmt.Errorf("UnmarshalPDLwSlackProof, part 3, expected len %d but copied %d", 3, len3)
	}
	p := new(PDLwSlackProof)
	p.Z = parsed[0][0]
	U1, err := crypto.NewECPoint(tss.EC(), parsed[1][0], parsed[1][1])
	if err != nil {
		return nil, err
	}
	p.U1 = U1
	p.U2, p.U3 = parsed[1][2], parsed[1][3]
	p.S1, p.S2, p.S3 = parsed[2][0], parsed[2][1], parsed[2][2]
	return p, nil
}

// https://github.com/KZen-networks/multi-party-ecdsa/blob/gg20/src/utilities/zk_pdl_with_slack/mod.rs#L175
func commitmentUnknownOrder(h1, h2, NTilde, x, r *big.Int) (com *big.Int) {
	modNTilde := common.ModInt(NTilde)
	h1X := modNTilde.Exp(h1, x)
	h2R := modNTilde.Exp(h2, r)
	com = modNTilde.Mul(h1X, h2R)
	return
}

// TODO: add tests
