package mta

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

type (
	ProofBob struct {
		Z, ZPrm, T, V, W, S, S1, S2, T1, T2 *big.Int
	}

	ProofBobWC struct {
		*ProofBob
		U *crypto.ECPoint
	}
)

// ProveBobWC implements Bob's proof both with or without check "ProveMtawc_Bob" and "ProveMta_Bob" used in the MtA protocol from GG18Spec (9) Figs. 10 & 11.
// an absent `X` generates the proof without the X consistency check X = g^x
func ProveBobWC(pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int, X *crypto.ECPoint) (*ProofBobWC, error) {
	if pk == nil || NTilde == nil || h1 == nil || h2 == nil || c1 == nil || c2 == nil || x == nil || y == nil || r == nil {
		return nil, errors.New("ProveBob() received a nil argument")
	}

	NSquared := pk.NSquare()

	q := tss.EC().Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	qNTilde := new(big.Int).Mul(q, NTilde)
	q3NTilde := new(big.Int).Mul(q3, NTilde)

	// steps are numbered as shown in Fig. 10, but diverge slightly for Fig. 11
	// 1.
	alpha := random.GetRandomPositiveInt(q3)

	// 2.
	rho := random.GetRandomPositiveInt(qNTilde)
	sigma := random.GetRandomPositiveInt(qNTilde)
	tau := random.GetRandomPositiveInt(qNTilde)

	// 3.
	rhoPrm := random.GetRandomPositiveInt(q3NTilde)

	// 4.
	beta := random.GetRandomPositiveRelativelyPrimeInt(pk.N)
	gamma := random.GetRandomPositiveRelativelyPrimeInt(pk.N)

	// 5.
	var u *crypto.ECPoint
	if X != nil {
		u = crypto.ScalarBaseMult(tss.EC(), alpha)
	}

	// 6.
	z := new(big.Int).Exp(h1, x, NTilde)
	z = new(big.Int).Mul(z, new(big.Int).Exp(h2, rho, NTilde))
	z = new(big.Int).Mod(z, NTilde)

	// 7.
	zPrm := new(big.Int).Exp(h1, alpha, NTilde)
	zPrm = new(big.Int).Mul(zPrm, new(big.Int).Exp(h2, rhoPrm, NTilde))
	zPrm = new(big.Int).Mod(zPrm, NTilde)

	// 8.
	t := new(big.Int).Exp(h1, y, NTilde)
	t = new(big.Int).Mul(t, new(big.Int).Exp(h2, sigma, NTilde))
	t = new(big.Int).Mod(t, NTilde)

	// 9.
	v := new(big.Int).Exp(c1, alpha, NSquared)
	v = new(big.Int).Mul(v, new(big.Int).Exp(pk.Gamma, gamma, NSquared))
	v = new(big.Int).Mul(v, new(big.Int).Exp(beta, pk.N, NSquared))
	v = new(big.Int).Mod(v, NSquared)

	// 10.
	w := new(big.Int).Exp(h1, gamma, NTilde)
	w = new(big.Int).Mul(w, new(big.Int).Exp(h2, tau, NTilde))
	w = new(big.Int).Mod(w, NTilde)

	// 11-12. e'
	var e *big.Int
	{ // must use RejectionSample
		var eHash *big.Int
		// X is nil if called by ProveBob (Bob's proof "without check")
		if X == nil {
			eHash = common.SHA512_256i(append(pk.AsInts(), c1, c2, z, zPrm, t, v, w)...)
		} else {
			eHash = common.SHA512_256i(append(pk.AsInts(), X.X(), X.Y(), c1, c2, z, zPrm, t, v, w)...)
		}
		e = common.RejectionSample(q, eHash)
	}

	// 13.
	s := new(big.Int).Exp(r, e, pk.N)
	s = new(big.Int).Mul(s, beta)
	s = new(big.Int).Mod(s, pk.N)

	// 14.
	s1 := new(big.Int).Mul(e, x)
	s1 = new(big.Int).Add(s1, alpha)

	// 15.
	s2 := new(big.Int).Mul(e, rho)
	s2 = new(big.Int).Add(s2, rhoPrm)

	// 16.
	t1 := new(big.Int).Mul(e, y)
	t1 = new(big.Int).Add(t1, gamma)

	// 17.
	t2 := new(big.Int).Mul(e, sigma)
	t2 = new(big.Int).Add(t2, tau)

	// the regular Bob proof ("without check") is extracted and returned by ProveBob
	pf := &ProofBob{Z: z, ZPrm: zPrm, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}

	// or the WC ("with check") version is used in round 2 of the signing protocol
	return &ProofBobWC{ProofBob: pf, U: u}, nil
}

// ProveBob implements Bob's proof "ProveMta_Bob" used in the MtA protocol from GG18Spec (9) Fig. 11.
func ProveBob(pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int) (*ProofBob, error) {
	// the Bob proof ("with check") contains the ProofBob "without check"; this method extracts and returns it
	// X is supplied as nil to exclude it from the proof hash
	pf, err := ProveBobWC(pk, NTilde, h1, h2, c1, c2, x, y, r, nil)
	if err != nil {
		return nil, err
	}
	return pf.ProofBob, nil
}

// ProveBobWC.Verify implements verification of Bob's proof with check "VerifyMtawc_Bob" used in the MtA protocol from GG18Spec (9) Fig. 10.
// an absent `X` verifies a proof generated without the X consistency check X = g^x
func (pf *ProofBobWC) Verify(pk *paillier.PublicKey, NTilde, h1, h2, c1, c2 *big.Int, X *crypto.ECPoint) bool {
	if pk == nil || NTilde == nil || h1 == nil || h2 == nil || c1 == nil || c2 == nil {
		return false
	}

	NSquared := pk.NSquare()

	q := tss.EC().Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)

	// 3.
	if pf.S1.Cmp(q3) > 0 {
		return false
	}

	// 1-2. e'
	var e *big.Int
	{ // must use RejectionSample
		var eHash *big.Int
		// X is nil if called on a ProveBob (Bob's proof "without check")
		if X == nil {
			eHash = common.SHA512_256i(append(pk.AsInts(), c1, c2, pf.Z, pf.ZPrm, pf.T, pf.V, pf.W)...)
		} else {
			eHash = common.SHA512_256i(append(pk.AsInts(), X.X(), X.Y(), c1, c2, pf.Z, pf.ZPrm, pf.T, pf.V, pf.W)...)
		}
		e = common.RejectionSample(q, eHash)
	}

	var left, right *big.Int // for the following conditionals

	// 4. runs only in the "with check" mode from Fig. 10
	if X != nil {
		s1ModQ := new(big.Int).Mod(pf.S1, tss.EC().Params().N)
		gS1 := crypto.ScalarBaseMult(tss.EC(), s1ModQ)
		xEU := X.ScalarMult(e).Add(pf.U)
		if !gS1.IsOnCurve() || !xEU.IsOnCurve() || !gS1.Equals(xEU) {
			return false
		}
	}

	{ // 5.
		h1ExpS1 := new(big.Int).Exp(h1, pf.S1, NTilde)
		h2ExpS2 := new(big.Int).Exp(h2, pf.S2, NTilde)
		left = new(big.Int).Mul(h1ExpS1, h2ExpS2)
		left = new(big.Int).Mod(left, NTilde)
		zExpE := new(big.Int).Exp(pf.Z, e, NTilde)
		right = new(big.Int).Mul(zExpE, pf.ZPrm)
		right = new(big.Int).Mod(right, NTilde)
		if left.Cmp(right) != 0 {
			return false
		}
	}

	{ // 6.
		h1ExpT1 := new(big.Int).Exp(h1, pf.T1, NTilde)
		h2ExpT2 := new(big.Int).Exp(h2, pf.T2, NTilde)
		left = new(big.Int).Mul(h1ExpT1, h2ExpT2)
		left = new(big.Int).Mod(left, NTilde)
		tExpE := new(big.Int).Exp(pf.T, e, NTilde)
		right = new(big.Int).Mul(tExpE, pf.W)
		right = new(big.Int).Mod(right, NTilde)
		if left.Cmp(right) != 0 {
			return false
		}
	}

	{ // 7.
		c1ExpS1 := new(big.Int).Exp(c1, pf.S1, NSquared)
		sExpN := new(big.Int).Exp(pf.S, pk.N, NSquared)
		gammaExpT1 := new(big.Int).Exp(pk.Gamma, pf.T1, NSquared)
		left = new(big.Int).Mul(c1ExpS1, sExpN)
		left = new(big.Int).Mul(left, gammaExpT1)
		left = new(big.Int).Mod(left, NSquared)
		c2ExpE := new(big.Int).Exp(c2, e, NSquared)
		right = new(big.Int).Mul(c2ExpE, pf.V)
		right = new(big.Int).Mod(right, NSquared)
		if left.Cmp(right) != 0 {
			return false
		}
	}
	return true
}

// ProveBob.Verify implements verification of Bob's proof without check "VerifyMta_Bob" used in the MtA protocol from GG18Spec (9) Fig. 11.
func (pf *ProofBob) Verify(pk *paillier.PublicKey, NTilde, h1, h2, c1, c2 *big.Int) bool {
	if pf == nil {
		return false
	}
	pfWC := &ProofBobWC{ProofBob: pf, U: nil}
	return pfWC.Verify(pk, NTilde, h1, h2, c1, c2, nil)
}

func (pf *ProofBob) GobEncode() ([]byte, error) {
	buf := &bytes.Buffer{}
	z, err := pf.Z.GobEncode()
	if err != nil {
		return nil, err
	}
	zPrm, err := pf.ZPrm.GobEncode()
	if err != nil {
		return nil, err
	}
	t, err := pf.T.GobEncode()
	if err != nil {
		return nil, err
	}
	v, err := pf.V.GobEncode()
	if err != nil {
		return nil, err
	}
	w, err := pf.W.GobEncode()
	if err != nil {
		return nil, err
	}
	s, err := pf.S.GobEncode()
	if err != nil {
		return nil, err
	}
	s1, err := pf.S1.GobEncode()
	if err != nil {
		return nil, err
	}
	s2, err := pf.S2.GobEncode()
	if err != nil {
		return nil, err
	}
	t1, err := pf.T1.GobEncode()
	if err != nil {
		return nil, err
	}
	t2, err := pf.T2.GobEncode()
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, uint32(len(z)))
	if err != nil {
		return nil, err
	}
	buf.Write(z)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(zPrm)))
	if err != nil {
		return nil, err
	}
	buf.Write(zPrm)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(t)))
	if err != nil {
		return nil, err
	}
	buf.Write(t)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(v)))
	if err != nil {
		return nil, err
	}
	buf.Write(v)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(w)))
	if err != nil {
		return nil, err
	}
	buf.Write(w)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(s)))
	if err != nil {
		return nil, err
	}
	buf.Write(s)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(s1)))
	if err != nil {
		return nil, err
	}
	buf.Write(s1)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(s2)))
	if err != nil {
		return nil, err
	}
	buf.Write(s2)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(t1)))
	if err != nil {
		return nil, err
	}
	buf.Write(t1)
	err = binary.Write(buf, binary.LittleEndian, uint32(len(t2)))
	if err != nil {
		return nil, err
	}
	buf.Write(t2)

	return buf.Bytes(), nil
}

func (pf *ProofBob) GobDecode(buf []byte) error {
	reader := bytes.NewReader(buf)
	var length uint32
	binary.Read(reader, binary.LittleEndian, &length)
	z := make([]byte, length)
	n, err := reader.Read(z)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	zPrm := make([]byte, length)
	n, err = reader.Read(zPrm)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	t := make([]byte, length)
	n, err = reader.Read(t)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	v := make([]byte, length)
	n, err = reader.Read(v)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	w := make([]byte, length)
	n, err = reader.Read(w)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	s := make([]byte, length)
	n, err = reader.Read(s)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	s1 := make([]byte, length)
	n, err = reader.Read(s1)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	s2 := make([]byte, length)
	n, err = reader.Read(s2)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	t1 := make([]byte, length)
	n, err = reader.Read(t1)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}
	binary.Read(reader, binary.LittleEndian, &length)
	t2 := make([]byte, length)
	n, err = reader.Read(t2)
	if n != int(length) || err != nil {
		return fmt.Errorf("gob decode failed: %v", err)
	}

	pf.Z = new(big.Int)
	pf.ZPrm = new(big.Int)
	pf.T = new(big.Int)
	pf.V = new(big.Int)
	pf.W = new(big.Int)
	pf.S = new(big.Int)
	pf.S1 = new(big.Int)
	pf.S2 = new(big.Int)
	pf.T1 = new(big.Int)
	pf.T2 = new(big.Int)

	pf.Z.GobDecode(z)
	pf.ZPrm.GobDecode(zPrm)
	pf.T.GobDecode(t)
	pf.V.GobDecode(v)
	pf.W.GobDecode(w)
	pf.S.GobDecode(s)
	pf.S1.GobDecode(s1)
	pf.S2.GobDecode(s2)
	pf.T1.GobDecode(t1)
	pf.T2.GobDecode(t2)

	return nil
}

func (pf *ProofBobWC) GobEncode() ([]byte, error) {
	buf := &bytes.Buffer{}
	bob, err := pf.ProofBob.GobEncode()
	if err != nil {
		return nil, err
	}
	UX := pf.U.X()
	ux, err := UX.GobEncode()
	if err != nil {
		return nil, err
	}
	UY := pf.U.Y()
	uy, err := UY.GobEncode()
	if err != nil {
		return nil, err
	}

	binary.Write(buf, binary.LittleEndian, uint32(len(bob)))
	buf.Write(bob)
	binary.Write(buf, binary.LittleEndian, uint32(len(ux)))
	buf.Write(ux)
	binary.Write(buf, binary.LittleEndian, uint32(len(uy)))
	buf.Write(uy)

	return buf.Bytes(), nil
}

func (pf *ProofBobWC) GobDecode(buf []byte) error {
	reader := bytes.NewReader(buf)
	var length uint32

	binary.Read(reader, binary.LittleEndian, &length)
	bob := make([]byte, length)
	n, err := reader.Read(bob)
	if n != int(length) || err != nil {
		return fmt.Errorf("failed to gob decode: %v", err)
	}

	binary.Read(reader, binary.LittleEndian, &length)
	ux := make([]byte, length)
	n, err = reader.Read(ux)
	if n != int(length) || err != nil {
		return fmt.Errorf("failed to gob decode: %v", err)
	}

	binary.Read(reader, binary.LittleEndian, &length)
	uy := make([]byte, length)
	n, err = reader.Read(uy)
	if n != int(length) || err != nil {
		return fmt.Errorf("failed to gob decode: %v", err)
	}

	UX := new(big.Int)
	UY := new(big.Int)
	UX.GobDecode(ux)
	UY.GobDecode(uy)

	pf.ProofBob = new(ProofBob)
	pf.ProofBob.GobDecode(bob)
	pf.U = crypto.NewECPoint(tss.EC(), UX, UY)
	return nil
}
