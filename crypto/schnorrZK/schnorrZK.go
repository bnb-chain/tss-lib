package schnorrZK

import (
	"math/big"

	"golang.org/x/crypto/sha3"

	"github.com/binance-chain/tss-lib/common/math"
)

const (
	SAMPLE = "BNC_PLAINTEXT"
)

type ZKProof struct {
	E *big.Int
	S *big.Int
}

func NewZKProof(x *big.Int) *ZKProof {
	r := math.GetRandomPositiveInt(EC().N)
	rGx, rGy := EC().ScalarBaseMult(r.Bytes())

	plain   := SAMPLE
	sha3256 := sha3.New256()
	sha3256.Write(rGx.Bytes())
	sha3256.Write(rGy.Bytes())
	sha3256.Write([]byte(plain))
	eBytes  := sha3256.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	s := new(big.Int).Mul(e, x)
	s  = new(big.Int).Add(r, s)
	s  = new(big.Int).Mod(s, EC().N)

	return &ZKProof{E: e, S: s}
}

func (pf *ZKProof) Verify(uG []*big.Int) bool {
	sGx, sGy := EC().ScalarBaseMult(pf.S.Bytes())

	minusE := new(big.Int).Mul(big.NewInt(-1), pf.E)
	minusE  = new(big.Int).Mod(minusE, EC().N)

	eUx, eUy := EC().ScalarMult(uG[0], uG[1], minusE.Bytes())
	rGx, rGy := EC().Add(sGx, sGy, eUx, eUy)

	plain := SAMPLE
	sha3256 := sha3.New256()
	sha3256.Write(rGx.Bytes())
	sha3256.Write(rGy.Bytes())
	sha3256.Write([]byte(plain))
	eBytes := sha3256.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	if e.Cmp(pf.E) == 0 {
		return true
	} else {
		return false
	}
}
