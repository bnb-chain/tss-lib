// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

const (
	ProofBobBytesParts   = 10
	ProofBobWCBytesParts = 12
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
func ProveBobWC(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int, X *crypto.ECPoint, rand io.Reader) (*ProofBobWC, error) {
	if pk == nil || NTilde == nil || h1 == nil || h2 == nil || c1 == nil || c2 == nil || x == nil || y == nil || r == nil {
		return nil, errors.New("ProveBob() received a nil argument")
	}
	// (NTilde, h1, h2) is the counterparty's here too -- Bob proves under Alice's
	// ring and Alice verifies. See ErrCounterpartyRingUnusable.
	if !counterpartyRingUsable(NTilde, h1, h2) {
		return nil, ErrCounterpartyRingUnusable
	}

	NSquared := pk.NSquare()

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	q7 := new(big.Int).Mul(q3, q3)
	q7 = new(big.Int).Mul(q7, q)
	qNTilde := new(big.Int).Mul(q, NTilde)
	q3NTilde := new(big.Int).Mul(q3, NTilde)

	// steps are numbered as shown in Fig. 10, but diverge slightly for Fig. 11
	// 1.
	alpha := common.GetRandomPositiveInt(rand, q3)

	// 2.
	rho := common.GetRandomPositiveInt(rand, qNTilde)
	sigma := common.GetRandomPositiveInt(rand, qNTilde)
	tau := common.GetRandomPositiveInt(rand, q3NTilde)

	// 3.
	rhoPrm := common.GetRandomPositiveInt(rand, q3NTilde)

	// 4.
	beta := common.GetRandomPositiveRelativelyPrimeInt(rand, pk.N)

	gamma := common.GetRandomPositiveInt(rand, q7)

	// 5.
	u := crypto.NewECPointNoCurveCheck(ec, zero, zero) // initialization suppresses an IDE warning
	if X != nil {
		u = crypto.ScalarBaseMult(ec, alpha)
	}

	// 6.
	modNTilde := common.ModInt(NTilde)
	var ctModNTilde *common.CTModInt
	if common.IsConstantTimeEnabled() {
		ctModNTilde = common.NewCTModInt(NTilde)
	}

	var z *big.Int
	if ctModNTilde != nil {
		// SECURITY: Use constant-time exponentiation for secret x
		// See: https://github.com/golang/go/issues/20654
		z = ctModNTilde.ExpCT(h1, x)
	} else {
		z = modNTilde.Exp(h1, x)
	}
	z = modNTilde.Mul(z, modNTilde.Exp(h2, rho)) // rho is random, not secret

	// 7.
	zPrm := modNTilde.Exp(h1, alpha)
	zPrm = modNTilde.Mul(zPrm, modNTilde.Exp(h2, rhoPrm))

	// 8.
	var t *big.Int
	if ctModNTilde != nil {
		// SECURITY: Use constant-time exponentiation for secret y
		t = ctModNTilde.ExpCT(h1, y)
	} else {
		t = modNTilde.Exp(h1, y)
	}
	t = modNTilde.Mul(t, modNTilde.Exp(h2, sigma)) // sigma is random, not secret

	// 9.
	modNSquared := common.ModInt(NSquared)
	v := modNSquared.Exp(c1, alpha)
	v = modNSquared.Mul(v, modNSquared.Exp(pk.Gamma(), gamma))
	v = modNSquared.Mul(v, modNSquared.Exp(beta, pk.N))

	// 10.
	w := modNTilde.Exp(h1, gamma)
	w = modNTilde.Mul(w, modNTilde.Exp(h2, tau))

	// 11-12. e'
	var e *big.Int
	{ // must use RejectionSample
		var eHash *big.Int
		// X is nil if called by ProveBob (Bob's proof "without check")
		if X == nil {
			eHash = common.SHA512_256i_TAGGED(fsSessionBob(Session), append(pk.AsInts(), NTilde, h1, h2, c1, c2, z, zPrm, t, v, w)...)
		} else {
			eHash = common.SHA512_256i_TAGGED(fsSessionBobWC(Session), append(pk.AsInts(), NTilde, h1, h2, X.X(), X.Y(), c1, c2, u.X(), u.Y(), z, zPrm, t, v, w)...)
		}
		e = common.ModReduceHash(q, eHash)
	}

	// 13.
	modN := common.ModInt(pk.N)
	s := modN.Exp(r, e)
	s = modN.Mul(s, beta)

	// 14.
	s1 := new(big.Int).Mul(e, x)
	s1 = s1.Add(s1, alpha)

	// 15.
	s2 := new(big.Int).Mul(e, rho)
	s2 = s2.Add(s2, rhoPrm)

	// 16.
	t1 := new(big.Int).Mul(e, y)
	t1 = t1.Add(t1, gamma)

	// 17.
	t2 := new(big.Int).Mul(e, sigma)
	t2 = t2.Add(t2, tau)

	// Do not hand out a proof whose ring-side values the counterparty's own
	// verifier rejects: Z, ZPrm, T and W are the four values computed in the
	// counterparty's ring. See ringSideValuesUsable for why only these four.
	if !ringSideValuesUsable(NTilde, z, zPrm, t, w) {
		return nil, ErrCounterpartyRingUnusable
	}

	// the regular Bob proof ("without check") is extracted and returned by ProveBob
	pf := &ProofBob{Z: z, ZPrm: zPrm, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}

	// or the WC ("with check") version is used in round 2 of the signing protocol
	return &ProofBobWC{ProofBob: pf, U: u}, nil
}

// ProveBob implements Bob's proof "ProveMta_Bob" used in the MtA protocol from GG18Spec (9) Fig. 11.
func ProveBob(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int, rand io.Reader) (*ProofBob, error) {
	// the Bob proof ("with check") contains the ProofBob "without check"; this method extracts and returns it
	// X is supplied as nil to exclude it from the proof hash
	pf, err := ProveBobWC(Session, ec, pk, NTilde, h1, h2, c1, c2, x, y, r, nil, rand)
	if err != nil {
		return nil, err
	}
	return pf.ProofBob, nil
}

func ProofBobWCFromBytes(ec elliptic.Curve, bzs [][]byte) (*ProofBobWC, error) {
	// ProofBobFromBytes accepts EITHER arity on purpose -- a ProofBobWC's first
	// ten parts are a well-formed ProofBob -- so delegating to it does not
	// establish that parts 10 and 11 exist. Require the WC arity here, before
	// reading them, or a ten-part input walks past the end of the slice.
	if !common.NonEmptyMultiBytes(bzs, ProofBobWCBytesParts) {
		return nil, fmt.Errorf(
			"expected %d byte parts to construct ProofBobWC", ProofBobWCBytesParts)
	}
	proofBob, err := ProofBobFromBytes(bzs)
	if err != nil {
		return nil, err
	}
	point, err := crypto.NewECPoint(ec,
		new(big.Int).SetBytes(bzs[10]),
		new(big.Int).SetBytes(bzs[11]))
	if err != nil {
		return nil, err
	}
	return &ProofBobWC{
		ProofBob: proofBob,
		U:        point,
	}, nil
}

func ProofBobFromBytes(bzs [][]byte) (*ProofBob, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofBobBytesParts) &&
		!common.NonEmptyMultiBytes(bzs, ProofBobWCBytesParts) {
		return nil, fmt.Errorf(
			"expected %d byte parts to construct ProofBob, or %d for ProofBobWC",
			ProofBobBytesParts, ProofBobWCBytesParts)
	}
	return &ProofBob{
		Z:    new(big.Int).SetBytes(bzs[0]),
		ZPrm: new(big.Int).SetBytes(bzs[1]),
		T:    new(big.Int).SetBytes(bzs[2]),
		V:    new(big.Int).SetBytes(bzs[3]),
		W:    new(big.Int).SetBytes(bzs[4]),
		S:    new(big.Int).SetBytes(bzs[5]),
		S1:   new(big.Int).SetBytes(bzs[6]),
		S2:   new(big.Int).SetBytes(bzs[7]),
		T1:   new(big.Int).SetBytes(bzs[8]),
		T2:   new(big.Int).SetBytes(bzs[9]),
	}, nil
}

// ProveBobWC.Verify implements verification of Bob's proof with check "VerifyMtawc_Bob" used in the MtA protocol from GG18Spec (9) Fig. 10.
// an absent `X` verifies a proof generated without the X consistency check X = g^x
func (pf *ProofBobWC) Verify(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2 *big.Int, X *crypto.ECPoint) bool {
	if pf == nil || pf.ProofBob == nil || !pf.ProofBob.ValidateBasic() || ec == nil || pk == nil || pk.N == nil || NTilde == nil || h1 == nil || h2 == nil || c1 == nil || c2 == nil {
		return false
	}
	if X != nil && pf.U == nil {
		return false
	}
	// pk.N and NTilde must be plausible unknown-order moduli before any
	// modular arithmetic runs. NTilde and the public generators h1, h2
	// arrive from the peer's keygen output, so the verifier must validate
	// canonical-group shape rather than trust the upstream.
	if !common.IsUsableUnknownOrderModulus(pk.N, verifyMinModulusBitLen) {
		return false
	}
	if !common.IsUsableUnknownOrderModulus(NTilde, verifyMinModulusBitLen) {
		return false
	}
	if !common.IsCanonicalGenerator(NTilde, h1) || !common.IsCanonicalGenerator(NTilde, h2) || h1.Cmp(h2) == 0 {
		return false
	}
	// c1, c2 are Paillier ciphertexts from peers; reject non-canonical
	// representations and any value sharing a factor with N (which would
	// otherwise leak that factor through c^S1 mod N² or c^e mod N²).
	if !common.IsCanonicalPaillierCiphertext(c1, pk.N) || !common.IsCanonicalPaillierCiphertext(c2, pk.N) {
		return false
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)   // q^2
	q3 = new(big.Int).Mul(q, q3)   // q^3
	q7 := new(big.Int).Mul(q3, q3) // q^6
	q7 = new(big.Int).Mul(q7, q)   // q^7
	upperS2T2 := new(big.Int).Mul(q3, NTilde)
	upperS2T2.Lsh(upperS2T2, 1)

	if !common.IsInIntervalPositive(pf.Z, NTilde) {
		return false
	}
	if !common.IsInIntervalPositive(pf.ZPrm, NTilde) {
		return false
	}
	if !common.IsInIntervalPositive(pf.T, NTilde) {
		return false
	}
	if !common.IsInIntervalPositive(pf.V, pk.NSquare()) {
		return false
	}
	if !common.IsInIntervalPositive(pf.W, NTilde) {
		return false
	}
	if !common.IsInIntervalPositive(pf.S, pk.N) {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.Z, NTilde).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.ZPrm, NTilde).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.T, NTilde).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.V, pk.NSquare()).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.W, NTilde).Cmp(one) != 0 {
		return false
	}

	gcd := big.NewInt(0)
	if pf.S.Cmp(zero) == 0 {
		return false
	}
	if gcd.GCD(nil, nil, pf.S, pk.N).Cmp(one) != 0 {
		return false
	}
	if pf.V.Cmp(zero) == 0 {
		return false
	}
	// gcd(V, pk.N²) above (line ~273) already implies gcd(V, pk.N) since
	// N and N² share the same prime factors; no redundant check here.
	if pf.S1.Cmp(q) == -1 {
		return false
	}
	if pf.S2.Cmp(q) == -1 {
		return false
	}
	if pf.T1.Cmp(q) == -1 {
		return false
	}
	if pf.T2.Cmp(q) == -1 {
		return false
	}
	if pf.S2.Cmp(upperS2T2) >= 0 {
		return false
	}
	if pf.T2.Cmp(upperS2T2) >= 0 {
		return false
	}

	// 3.
	if pf.S1.Cmp(q3) > 0 {
		return false
	}
	if pf.T1.Cmp(q7) > 0 {
		return false
	}

	// 1-2. e'
	var e *big.Int
	{ // must use RejectionSample
		var eHash *big.Int
		// X is nil if called on a ProveBob (Bob's proof "without check")
		if X == nil {
			eHash = common.SHA512_256i_TAGGED(fsSessionBob(Session), append(pk.AsInts(), NTilde, h1, h2, c1, c2, pf.Z, pf.ZPrm, pf.T, pf.V, pf.W)...)
		} else {
			if !tss.SameCurve(ec, X.Curve()) {
				return false
			}
			eHash = common.SHA512_256i_TAGGED(fsSessionBobWC(Session), append(pk.AsInts(), NTilde, h1, h2, X.X(), X.Y(), c1, c2, pf.U.X(), pf.U.Y(), pf.Z, pf.ZPrm, pf.T, pf.V, pf.W)...)
		}
		e = common.ModReduceHash(q, eHash)
	}
	// Reject e == 0 for both with-check and without-check variants.
	// Negligible under Fiat-Shamir but a zero challenge collapses the Σ
	// relation binding, and consistency with Schnorr / RangeProofAlice
	// keeps the rejection policy uniform across the repo.
	if e.Sign() == 0 {
		return false
	}

	var left, right *big.Int // for the following conditionals

	// 4. runs only in the "with check" mode from Fig. 10
	if X != nil {
		// ValidateInSubgroup: same as ValidateBasic plus prime-order
		// subgroup membership on composite-cofactor curves. pf.U is
		// usually validated by the deserialization path's NewECPoint,
		// but direct API consumers can bypass that — keep the explicit
		// check here. Same-curve guards against cross-curve mixing
		// via NewECPointNoCurveCheck.
		if !X.ValidateInSubgroup() || !pf.U.ValidateInSubgroup() || !tss.SameCurve(ec, pf.U.Curve()) {
			return false
		}
		s1ModQ := new(big.Int).Mod(pf.S1, ec.Params().N)
		gS1 := crypto.ScalarBaseMult(ec, s1ModQ)
		xE := X.ScalarMult(e)
		if xE == nil {
			return false
		}
		xEU, err := xE.Add(pf.U)
		if err != nil || gS1 == nil || !gS1.Equals(xEU) {
			return false
		}
	}

	{ // 5-6.
		modNTilde := common.ModInt(NTilde)

		{ // 5.
			h1ExpS1 := modNTilde.Exp(h1, pf.S1)
			h2ExpS2 := modNTilde.Exp(h2, pf.S2)
			left = modNTilde.Mul(h1ExpS1, h2ExpS2)
			zExpE := modNTilde.Exp(pf.Z, e)
			right = modNTilde.Mul(zExpE, pf.ZPrm)
			if left.Cmp(right) != 0 {
				return false
			}
		}

		{ // 6.
			h1ExpT1 := modNTilde.Exp(h1, pf.T1)
			h2ExpT2 := modNTilde.Exp(h2, pf.T2)
			left = modNTilde.Mul(h1ExpT1, h2ExpT2)
			tExpE := modNTilde.Exp(pf.T, e)
			right = modNTilde.Mul(tExpE, pf.W)
			if left.Cmp(right) != 0 {
				return false
			}
		}
	}

	{ // 7.
		modNSquared := common.ModInt(pk.NSquare())

		c1ExpS1 := modNSquared.Exp(c1, pf.S1)
		sExpN := modNSquared.Exp(pf.S, pk.N)
		gammaExpT1 := modNSquared.Exp(pk.Gamma(), pf.T1)
		left = modNSquared.Mul(c1ExpS1, sExpN)
		left = modNSquared.Mul(left, gammaExpT1)
		c2ExpE := modNSquared.Exp(c2, e)
		right = modNSquared.Mul(c2ExpE, pf.V)
		if left.Cmp(right) != 0 {
			return false
		}
	}
	return true
}

// ProveBob.Verify implements verification of Bob's proof without check "VerifyMta_Bob" used in the MtA protocol from GG18Spec (9) Fig. 11.
func (pf *ProofBob) Verify(Session []byte, ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2 *big.Int) bool {
	if pf == nil {
		return false
	}
	pfWC := &ProofBobWC{ProofBob: pf, U: nil}
	return pfWC.Verify(Session, ec, pk, NTilde, h1, h2, c1, c2, nil)
}

func (pf *ProofBob) ValidateBasic() bool {
	return pf != nil &&
		pf.Z != nil &&
		pf.ZPrm != nil &&
		pf.T != nil &&
		pf.V != nil &&
		pf.W != nil &&
		pf.S != nil &&
		pf.S1 != nil &&
		pf.S2 != nil &&
		pf.T1 != nil &&
		pf.T2 != nil
}

func (pf *ProofBobWC) ValidateBasic() bool {
	return pf != nil && pf.ProofBob != nil && pf.ProofBob.ValidateBasic() && pf.U != nil
}

// Bytes serialises the proof. It requires a well-formed receiver and says so by
// panicking, because there is no honest alternative: the return type is a fixed
// array of byte slices with no error channel, and substituting an empty slice
// for a missing field would emit a proof that looks serialisable and is not.
// ValidateBasic is the type's own definition of well-formed, so it is what the
// guard tests -- a nil field would otherwise fault inside (*big.Int).Bytes().
func (pf *ProofBob) Bytes() [ProofBobBytesParts][]byte {
	if !pf.ValidateBasic() {
		panic(fmt.Errorf("ProofBob.Bytes: receiver is nil or has a nil field; ValidateBasic must hold first"))
	}
	return [...][]byte{
		pf.Z.Bytes(),
		pf.ZPrm.Bytes(),
		pf.T.Bytes(),
		pf.V.Bytes(),
		pf.W.Bytes(),
		pf.S.Bytes(),
		pf.S1.Bytes(),
		pf.S2.Bytes(),
		pf.T1.Bytes(),
		pf.T2.Bytes(),
	}
}

// Bytes serialises the proof. Like ProofBob.Bytes it demands a well-formed
// receiver. Delegating to ProofBob.Bytes does NOT cover this type's own two
// extra obligations: pf.ProofBob must be non-nil to delegate at all, and pf.U
// must be non-nil before X()/Y() read its coordinates. ProofBobWC.ValidateBasic
// asserts exactly those two on top of the embedded proof's own check.
func (pf *ProofBobWC) Bytes() [ProofBobWCBytesParts][]byte {
	if !pf.ValidateBasic() {
		panic(fmt.Errorf("ProofBobWC.Bytes: receiver is nil, has a nil embedded ProofBob, a nil U, or a nil field; ValidateBasic must hold first"))
	}
	var out [ProofBobWCBytesParts][]byte
	bobBzs := pf.ProofBob.Bytes()
	bobBzsSlice := bobBzs[:]
	bobBzsSlice = append(bobBzsSlice, pf.U.X().Bytes())
	bobBzsSlice = append(bobBzsSlice, pf.U.Y().Bytes())
	copy(out[:], bobBzsSlice[:12])
	return out
}
