package schnorr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
)

type (
	ZKProof struct {
		Alpha *crypto.ECPoint
		T     *big.Int
	}

	ZKVProof struct {
		Alpha *crypto.ECPoint
		T,
		U *big.Int
	}
)

// NewZKProof constructs a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func NewZKProof(x *big.Int, X *crypto.ECPoint) *ZKProof {
	ecParams := tss.EC().Params()
	q := ecParams.N
	g := crypto.NewECPoint(tss.EC(), ecParams.Gx, ecParams.Gy)

	a := random.GetRandomPositiveInt(q)
	alpha := crypto.ScalarBaseMult(tss.EC(), a)

	var c *big.Int
	{ // must use RejectionSample
		cHash := common.SHA512_256i(X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	t := new(big.Int).Mul(c, x)
	t = new(big.Int).Add(a, t)
	t = new(big.Int).Mod(t, q)

	return &ZKProof{Alpha: alpha, T: t}
}

// NewZKProof verifies a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func (pf *ZKProof) Verify(X *crypto.ECPoint) bool {
	ecParams := tss.EC().Params()
	q := ecParams.N
	g := crypto.NewECPoint(tss.EC(), ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{ // must use RejectionSample
		cHash := common.SHA512_256i(X.X(), X.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	tG := crypto.ScalarBaseMult(tss.EC(), pf.T)
	Xc := X.ScalarMult(c)
	aXc := pf.Alpha.Add(Xc)

	if aXc.X().Cmp(tG.X()) != 0 || aXc.Y().Cmp(tG.Y()) != 0 {
		return false
	}
	return true
}

// NewZKProof constructs a new Schnorr ZK proof of knowledge s_i, l_i such that V_i = R^s_i, g^l_i (GG18Spec Fig. 17)
func NewZKVProof(V, R *crypto.ECPoint, s, l *big.Int) *ZKVProof {
	ecParams := tss.EC().Params()
	q := ecParams.N
	g := crypto.NewECPoint(tss.EC(), ecParams.Gx, ecParams.Gy)

	a, b := random.GetRandomPositiveInt(q), random.GetRandomPositiveInt(q)
	aR := R.ScalarMult(a)
	bG := crypto.ScalarBaseMult(tss.EC(), b)
	alpha := aR.Add(bG)

	var c *big.Int
	{ // must use RejectionSample
		cHash := common.SHA512_256i(V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	t := new(big.Int).Mod(new(big.Int).Add(a, new(big.Int).Mul(c, s)), q)
	u := new(big.Int).Mod(new(big.Int).Add(b, new(big.Int).Mul(c, l)), q)

	return &ZKVProof{Alpha: alpha, T: t, U: u}
}

func (pf *ZKVProof) Verify(V, R *crypto.ECPoint) bool {
	ecParams := tss.EC().Params()
	q := ecParams.N
	g := crypto.NewECPoint(tss.EC(), ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{ // must use RejectionSample
		cHash := common.SHA512_256i(V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = common.RejectionSample(q, cHash)
	}
	tR := R.ScalarMult(pf.T)
	uG := crypto.ScalarBaseMult(tss.EC(), pf.U)
	tRuG := tR.Add(uG)

	Vc := V.ScalarMult(c)
	aVc := pf.Alpha.Add(Vc)

	if tRuG.X().Cmp(aVc.X()) != 0 || tRuG.Y().Cmp(aVc.Y()) != 0 {
		return false
	}
	return true
}

func (pf *ZKProof) GobEncode() ([]byte, error) {
	buf := &bytes.Buffer{}
	AlphaX := pf.Alpha.X()
	alphax, err := AlphaX.GobEncode()
	if err != nil {
		return nil, err
	}
	AlphaY := pf.Alpha.Y()
	alphay, err := AlphaY.GobEncode()
	if err != nil {
		return nil, err
	}
	t, err := pf.T.GobEncode()
	if err != nil {
		return nil, err
	}

	binary.Write(buf, binary.LittleEndian, uint32(len(alphax)))
	buf.Write(alphax)
	binary.Write(buf, binary.LittleEndian, uint32(len(alphay)))
	buf.Write(alphay)
	binary.Write(buf, binary.LittleEndian, uint32(len(t)))
	buf.Write(t)

	return buf.Bytes(), nil
}

func (pf *ZKProof) GobDecode(buf []byte) error {
	reader := bytes.NewReader(buf)
	var length uint32
	binary.Read(reader, binary.LittleEndian, &length)
	alphax := make([]byte, length)
	n, err := reader.Read(alphax)
	if n != int(length) || err != nil {
		return fmt.Errorf("failed to gob decode: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	alphay := make([]byte, length)
	n, err = reader.Read(alphay)
	if n != int(length) || err != nil {
		return fmt.Errorf("failed to gob decode: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	t := make([]byte, length)
	n, err = reader.Read(t)
	if n != int(length) || err != nil {
		return fmt.Errorf("failed to gob decode: %v", err)
	}

	AlphaX := new(big.Int)
	AlphaY := new(big.Int)
	AlphaX.GobDecode(alphax)
	AlphaY.GobDecode(alphay)

	pf.Alpha = crypto.NewECPoint(tss.EC(), AlphaX, AlphaY)
	pf.T = new(big.Int)
	pf.T.GobDecode(t)
	return nil
}

func (pf *ZKVProof) GobEncode() ([]byte, error) {
	buf := &bytes.Buffer{}
	AlphaX := pf.Alpha.X()
	alphax, err := AlphaX.GobEncode()
	if err != nil {
		return nil, err
	}
	AlphaY := pf.Alpha.Y()
	alphay, err := AlphaY.GobEncode()
	if err != nil {
		return nil, err
	}
	u, err := pf.U.GobEncode()
	if err != nil {
		return nil, err
	}
	t, err := pf.T.GobEncode()
	if err != nil {
		return nil, err
	}

	binary.Write(buf, binary.LittleEndian, uint32(len(alphax)))
	buf.Write(alphax)
	binary.Write(buf, binary.LittleEndian, uint32(len(alphay)))
	buf.Write(alphay)
	binary.Write(buf, binary.LittleEndian, uint32(len(u)))
	buf.Write(u)
	binary.Write(buf, binary.LittleEndian, uint32(len(t)))
	buf.Write(t)

	return buf.Bytes(), nil
}

func (pf *ZKVProof) GobDecode(buf []byte) error {
	reader := bytes.NewReader(buf)
	var length uint32
	binary.Read(reader, binary.LittleEndian, &length)
	alphax := make([]byte, length)
	n, err := reader.Read(alphax)
	if n != int(length) || err != nil {
		return fmt.Errorf("failed to gob decode: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	alphay := make([]byte, length)
	n, err = reader.Read(alphay)
	if n != int(length) || err != nil {
		return fmt.Errorf("failed to gob decode: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	u := make([]byte, length)
	n, err = reader.Read(u)
	if n != int(length) || err != nil {
		return fmt.Errorf("failed to gob decode: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	t := make([]byte, length)
	n, err = reader.Read(t)
	if n != int(length) || err != nil {
		return fmt.Errorf("failed to gob decode: %v", err)
	}

	AlphaX := new(big.Int)
	AlphaY := new(big.Int)
	AlphaX.GobDecode(alphax)
	AlphaY.GobDecode(alphay)

	pf.Alpha = crypto.NewECPoint(tss.EC(), AlphaX, AlphaY)
	pf.U = new(big.Int)
	pf.T = new(big.Int)
	pf.U.GobDecode(u)
	pf.T.GobDecode(t)
	return nil
}
