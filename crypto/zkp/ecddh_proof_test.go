package zkp_test

import (
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/zkp"
)

var curve = btcec.S256()

func TestECDDHProof(t *testing.T) {
	x := common.MustGetRandomInt(256)
	g1 := crypto.NewECPointNoCurveCheck(curve, curve.Params().Gx, curve.Params().Gy)
	g2, _ := crypto.ECBasePoint2(curve)
	h1, h2 := g1.ScalarMult(x), g2.ScalarMult(x)
	st := zkp.ECDDHStatement{
		Curve: curve,
		G2:    g2,
		H1:    h1,
		H2:    h2,
	}
	wit := zkp.ECDDHWitness{X: x}
	pf := zkp.NewECDDHProof(wit, st)
	assert.True(t, pf.Verify(st))
}

func TestECDDHProof_Fail(t *testing.T) {
	x := common.MustGetRandomInt(256)
	x2 := common.MustGetRandomInt(256)
	g1 := crypto.NewECPointNoCurveCheck(curve, curve.Params().Gx, curve.Params().Gy)
	g2, _ := crypto.ECBasePoint2(curve)
	h1, h2 := g1.ScalarMult(x), g2.ScalarMult(x2)
	st := zkp.ECDDHStatement{
		Curve: curve,
		G2:    g2,
		H1:    h1,
		H2:    h2,
	}
	wit := zkp.ECDDHWitness{X: x}
	pf := zkp.NewECDDHProof(wit, st)
	assert.False(t, pf.Verify(st))
}
