// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package paillier_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/crypto"
	. "github.com/bnb-chain/tss-lib/v4/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v4/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

var (
	privateKey *PrivateKey
	publicKey  *PublicKey
)

func setUp(t *testing.T) {
	if privateKey != nil && publicKey != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var err error
	privateKey, publicKey, err = GenerateKeyPair(ctx, rand.Reader, testPaillierKeyLength)
	assert.NoError(t, err)
}

func TestGenerateKeyPair(t *testing.T) {
	setUp(t)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	t.Log(privateKey)
}

func TestEncrypt(t *testing.T) {
	setUp(t)
	cipher, err := publicKey.Encrypt(rand.Reader, big.NewInt(1))
	assert.NoError(t, err, "must not error")
	assert.NotZero(t, cipher)
	t.Log(cipher)
}

func TestEncryptDecrypt(t *testing.T) {
	setUp(t)
	exp := big.NewInt(100)
	cypher, err := privateKey.Encrypt(rand.Reader, exp)
	if err != nil {
		t.Error(err)
	}
	ret, err := privateKey.Decrypt(cypher)
	assert.NoError(t, err)
	assert.Equal(t, 0, exp.Cmp(ret),
		"wrong decryption ", ret, " is not ", exp)

	cypher = new(big.Int).Set(privateKey.N)
	_, err = privateKey.Decrypt(cypher)
	assert.Error(t, err)
}

func TestHomoMul(t *testing.T) {
	setUp(t)
	three, err := privateKey.Encrypt(rand.Reader, big.NewInt(3))
	assert.NoError(t, err)

	// for HomoMul, the first argument `m` is not ciphered
	six := big.NewInt(6)

	cm, err := privateKey.HomoMult(six, three)
	assert.NoError(t, err)
	multiple, err := privateKey.Decrypt(cm)
	assert.NoError(t, err)

	// 3 * 6 = 18
	exp := int64(18)
	assert.Equal(t, 0, multiple.Cmp(big.NewInt(exp)))
}

func TestHomoAdd(t *testing.T) {
	setUp(t)
	num1 := big.NewInt(10)
	num2 := big.NewInt(32)

	one, _ := publicKey.Encrypt(rand.Reader, num1)
	two, _ := publicKey.Encrypt(rand.Reader, num2)

	ciphered, _ := publicKey.HomoAdd(one, two)

	plain, _ := privateKey.Decrypt(ciphered)

	assert.Equal(t, new(big.Int).Add(num1, num2), plain)
}

func TestProofVerify(t *testing.T) {
	setUp(t)
	ki := common.MustGetRandomInt(rand.Reader, 256)                     // index
	ui := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N) // ECDSA private
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())                       // ECDSA public
	proof := privateKey.Proof(ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	res, err := proof.Verify(publicKey.N, ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	assert.NoError(t, err)
	assert.True(t, res, "proof verify result must be true")
}

func TestProofVerifyFail(t *testing.T) {
	setUp(t)
	ki := common.MustGetRandomInt(rand.Reader, 256)                     // index
	ui := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N) // ECDSA private
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())                       // ECDSA public
	proof := privateKey.Proof(ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	last := proof[len(proof)-1]
	last.Sub(last, big.NewInt(1))
	res, err := proof.Verify(publicKey.N, ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	assert.NoError(t, err)
	assert.False(t, res, "proof verify result must be true")
}

func TestComputeL(t *testing.T) {
	u := big.NewInt(21)
	n := big.NewInt(3)

	expected := big.NewInt(6)
	actual := L(u, n)

	assert.Equal(t, 0, expected.Cmp(actual))
}

func TestGenerateXs(t *testing.T) {
	k := common.MustGetRandomInt(rand.Reader, 256)
	sX := common.MustGetRandomInt(rand.Reader, 256)
	sY := common.MustGetRandomInt(rand.Reader, 256)
	N := common.GetRandomPrimeInt(rand.Reader, 2048)

	xs := GenerateXs(13, k, N, crypto.NewECPointNoCurveCheck(tss.EC(), sX, sY))
	assert.Equal(t, 13, len(xs))
	for _, xi := range xs {
		assert.True(t, common.IsNumberInMultiplicativeGroup(N, xi))
	}
}

func TestEncryptDecryptCT(t *testing.T) {
	setUp(t)
	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()

	exp := big.NewInt(100)
	cypher, err := privateKey.Encrypt(rand.Reader, exp)
	assert.NoError(t, err)

	ret, err := privateKey.Decrypt(cypher)
	assert.NoError(t, err)
	assert.Equal(t, 0, exp.Cmp(ret),
		"CT decryption mismatch: got ", ret, " expected ", exp)
}

// TestProofVerifyRejectsPrimePkN demonstrates the Fermat trivial-pass:
// for prime pkN, every xi ∈ Z_{pkN}* satisfies xi^pkN ≡ xi (mod pkN), so a
// proof with pf[i] = xs[i] passes the iteration check without proving any
// factorization. Verify must reject the modulus before that point.
func TestProofVerifyRejectsPrimePkN(t *testing.T) {
	ki := common.MustGetRandomInt(rand.Reader, 256)
	ui := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())
	pub := crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY)

	primePkN := common.GetRandomPrimeInt(rand.Reader, 2048)
	xs := GenerateXs(ProofIters, ki, primePkN, pub)
	var forged Proof
	for i := range forged {
		forged[i] = new(big.Int).Mod(xs[i], primePkN)
	}

	res, err := forged.Verify(primePkN, ki, pub)
	assert.NoError(t, err)
	assert.False(t, res, "Verify must reject a prime pkN even when iteration equality would otherwise hold")
}

func TestProofVerifyRejectsMalformedInputs(t *testing.T) {
	setUp(t)
	ki := common.MustGetRandomInt(rand.Reader, 256)
	ui := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())
	pub := crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY)
	good := privateKey.Proof(ki, pub)

	t.Run("nil pkN", func(t *testing.T) {
		res, err := good.Verify(nil, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("nil k", func(t *testing.T) {
		res, err := good.Verify(publicKey.N, nil, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("nil ecdsaPub", func(t *testing.T) {
		res, err := good.Verify(publicKey.N, ki, nil)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("pkN too small", func(t *testing.T) {
		small := big.NewInt(15) // 3*5, composite but tiny
		res, err := good.Verify(small, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("pkN even", func(t *testing.T) {
		even := new(big.Int).Lsh(publicKey.N, 1) // shift to make even, keep bit length
		res, err := good.Verify(even, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("pf[i] nil", func(t *testing.T) {
		var bad Proof
		copy(bad[:], good[:])
		bad[0] = nil
		res, err := bad.Verify(publicKey.N, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("pf[i] zero", func(t *testing.T) {
		var bad Proof
		copy(bad[:], good[:])
		bad[0] = big.NewInt(0)
		res, err := bad.Verify(publicKey.N, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("pf[i] out of range", func(t *testing.T) {
		var bad Proof
		copy(bad[:], good[:])
		bad[0] = new(big.Int).Add(publicKey.N, big.NewInt(1)) // > N
		res, err := bad.Verify(publicKey.N, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
	t.Run("pf[i] non-unit", func(t *testing.T) {
		var bad Proof
		copy(bad[:], good[:])
		// privateKey.P is a prime factor of publicKey.N, so gcd(P, N) = P > 1
		bad[0] = new(big.Int).Set(privateKey.P)
		res, err := bad.Verify(publicKey.N, ki, pub)
		assert.NoError(t, err)
		assert.False(t, res)
	})
}

func TestProofVerifyCT(t *testing.T) {
	setUp(t)
	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()

	ki := common.MustGetRandomInt(rand.Reader, 256)
	ui := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())
	proof := privateKey.Proof(ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	res, err := proof.Verify(publicKey.N, ki, crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY))
	assert.NoError(t, err)
	assert.True(t, res, "CT proof verify result must be true")
}

// ----- termination guards

const (
	// A fixed 2048-bit odd composite (product of two 1024-bit primes); 2048 is
	// a multiple of 256, which is the only case the challenge sampler used to
	// handle.
	n2048Hex = "900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002c26f33f80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b2586d8e829"
	// The same, one bit wider: 2049 mod 256 = 1.
	n2049Hex = "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006bc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a9b2b"
	// Every case below either returns promptly or never.
	terminationDeadline = 20 * time.Second
)

func mustParseHex(t *testing.T, s string) *big.Int {
	t.Helper()
	i, ok := new(big.Int).SetString(s, 16)
	assert.True(t, ok, "bad hex fixture")
	return i
}

// returnsWithin runs fn on its own goroutine and reports whether it returned
// before d elapsed. On timeout fn is abandoned rather than joined: it is a
// resample loop with a near-zero acceptance rate, so waiting for it would hang
// `go test` itself.
func returnsWithin(t *testing.T, d time.Duration, fn func()) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panicked: %v", r)
			}
		}()
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func fixedPub() *crypto.ECPoint {
	return crypto.NewECPointNoCurveCheck(tss.EC(), tss.EC().Params().Gx, tss.EC().Params().Gy)
}

// GenerateXs draws 256·⌈bits/256⌉-bit candidates but accepts only those below
// N, so for a modulus whose bit length is not a multiple of 256 the acceptance
// rate is ≈ 2^-(256 - bits mod 256) — as low as 2^-255. Masking the candidate
// to N's width brings it back above 1/2 for every N.
func TestGenerateXsTerminatesForAModulusThatIsNotAMultipleOf256Bits(t *testing.T) {
	N := mustParseHex(t, n2049Hex)
	assert.Equal(t, 2049, N.BitLen())
	var xs []*big.Int
	returned := returnsWithin(t, terminationDeadline, func() {
		xs = GenerateXs(ProofIters, big.NewInt(1234567), N, fixedPub())
	})
	assert.True(t, returned, "must return rather than resample forever")
	assert.Len(t, xs, ProofIters)
	for _, xi := range xs {
		assert.True(t, common.IsNumberInMultiplicativeGroup(N, xi))
	}
}

// The challenges are part of the proof transcript: changing any of them would
// invalidate every proof made by an older peer. These vectors were taken from
// the implementation before the mask was introduced.
func TestGenerateXsIsUnchangedForA2048BitModulus(t *testing.T) {
	N := mustParseHex(t, n2048Hex)
	assert.Equal(t, 2048, N.BitLen())
	want := []string{
		"643a0f2f79bf2869e3d2dd4ba7d0d62b4233a1d5d3097dae1dbfcaaa03bb368964071165fa398945bba59c8e45b0c78d024f261704806b3f7a28071e35b35987945a207e761df028beb150187359f5aa576a45b714d71091d8350f0740bbf3602543bdd0f371f3bc85af8caa113c05965ebc90a1df819a54802430a11632b9f2a458c2aec9599a3838e7ea68ccde5837fe6e66e528395ea6d773e2cf47e5ac019d70210b9ed701139f52cf33d0b07532b6883aa20b5f25676910b174c95a1faeb519da1925a299965959730ec222500f6c60a573798069fdb9812b38429789e1d783440d44c4ed2bb448bc4b681410e3fd001acd6d43a7e132d1a79a552b51e8",
		"74a8cf57278b1da42f6190c766f214cc04cb44e33f47a59cfcdf15560efb72fe1838881f68aa33be55e037d0b9a9a8f6b6970cbf3ce5a92553f789f2203de0a0931f3983a98c9ffc9610c69d08229de5018419e446e996fff507a87fda586a4ec15afc8e43fbb967c27d84bbfb75e7a05e26cacecbd3f9dfccd47c178858565ee1ad5d34385cf595f240c89fd1cd37d26fac89e869854010e26f999834e72c110c0f5b1d3547a5fdb037e566964a2c79a64faa58206486adda34f6ca779683da2a0661020c050cfa5276655cddfffa932795246e8c78f62ca131646963e6057ebf9bdc7cfdd2307b47d1d86fbc8f88f09a75083ed9005f5aa69d52396d7ef242",
		"54a6658974671f86754af7e4a39e4356a13d1a1e3e787813ffa77eebf3b1d2e1a38bb4ffe6ce26516408e85d9f3e2f4f97eff82ad58969d5086a0e218e644ca571e6a410556c76722197eb3cd488a94527a6a7871b08439541aa17f231d3fcd287046ce73fd42e60f1c8f3e398cbbec6e00397243b3a83d260d22223f90fec178be0b902962d3bc0e7623591635f0d570655e6103a073b50d4b6d7eb03aa1ef48fd07b927a955660546706b2cc75a57a1b965973afc389d8a72dfb7bd3e8d4559a0ecc2d7c0eade4414eea81d49d15c5f2a05ee253f33c2034b5b882db066fbdf1c7863a90410417eeb0b244bbb852f1cffa4f33c77a85657b6d81717f9c9023",
		"0fdac46c1c0737006999012eb33268ad187e1a7bd4dd86e0fa00a99de74227dfe1e70fb3eb4888f1a0960de5e0e6b18563758cfecd728b94ced625549bc18c49bf2caf5a5dce1021043e5cf75878f39f2f03fc514350b3e20d3865dc616deebb8321edb07d0401293c09647c1f21cf2259d171ff2d7ba78efe6620ca44b8fae8f7e125df785b01b0a54e531d140336abf86fa0f99e34d66fbb0633ff0be430c1580ae556620c409d4ef90e572e7706547b7f1060d12eca681bdc36c19ac3347ac782ffa8450ad9808f9f03aa828ba0c4d8a3ee0e271a525530a7be7d5236d7d34c03d8428573c047ed2365a67d22e6dcc6a553084124787000dc7bd4cb74358d",
		"7bf4a6c9b92b671eea16afe32e04c74af239416fa2a7c6fcad0af0f4de1f6c0753d8450591b6ba8a68fdfaf2849ecd9a7cad78c3d17f4758ec1637c5d63240307841e8d691453bbab76015e1147c39ce4392b697822a40f0648982e60a8763520c53fe3c18ceff524ff446ea0f4730ef9ce37cae5a284c8ef50741244ecca87235b8975560f52e7fc1f9e88c7975bbd8c171d979e9c7d705f66426ffbd8b4aca1982cb998de59b7856cd3ff0e2e9cc75dbd1ae11d60e6558d7d9d2d79c44bcc08fd7c3d722bbb1b62f768bc29744766b19a408ae0e9bddec230cb47830ff60113ba01b945fb9e7d504252ce02522974f756adb3e98751e50c8645cc2dd3b519c",
		"87fbbf765b5a66a343bf261eb56b8ec044bbe90aa713d70101427daa32bd0dabd7fc370476dd5e2e68ec2efe8e352262c47334774282f9d97449cbcd30cc57c1bc1419c37771af5ad5a58b57786b5702c90dc6db27e3b48cae34d49a77270de25f898a415cd6acf2cda9640db0a2fa4c481bc6db8e489243eebd32cb2f70634b1348f775f75e62289616313b20a0bd1681a0d5297e825a302703195d5f91ec4bb948cd53caf8d8a0d4113548b6e4e5137834103af5f8b7a315a24323604bd7070b6300ff7ea8e0df6c4365d409964a3d8458019676ba256e3eb1968b4d6a2c27e775be6532a6f32278a9913ab73406533810b4c4d2f460686deb8ddd3a37ef32",
		"8cf88094bb89328fe7b0b7d9fb9cc32635861e88ca70fff53dabaccb0bd50f1de60f8a1f70532b873d84c24c919f895f133d80993ae33be1dfb3483cb1f00cf73646ebb8c1418dba61661c57e76113603df49fb2feaff7556231333a0be4832554645fd4bf3643582f9b1936831623aed57539a7d0eeb8d236a3887cdb231ef2a70230483cbf9f131b7fdf8d6fd41a2e9f11a53e896411102006dccd4c4e303691c620c1bba2baa28fc3647698e001e19cf1b915c22fb3f38590209b718849b5f59d6da2e60bd19321f775ee15cbcd595f12bbadbb1a435b8f87a31a66733c6564d7f7ae8df2ae1ef37ee695b342dfec26c13548602bf74a5af98ee9696f94ec",
		"15ae5853a7d2e5bf7ddee042530bb76c57a3f58ea7d2e1600585b11bfb1a6959acc92770ed546443c56eb6ae001109eef9e0229c9c628b759eb64a504f227a544ed3b543a153cd821f5017f6387a622966902a673dc661368651a694505a1a415e49ffd4a5acb1a2c9bc1590af1e6b1b1f720270d289b5203460c0ef47a699795b74e6fe9a65604838180281b1cda473d57fb75d9d801cd9402a78c0ccca20da2a26933d58bfe19d6193e42b12519d03974b1b1829a960dd863c03496c6d4ad8e72e35b92df561d7badc09e48abf0ffaa8bfd3f0ee18ba1b45e0e79b08ecb8016f72b3eb9f0e44b8b9cb14814321374911c8fb020f1fabe1aa24d0aadc6f4384",
		"5f21e0e0ac3a316b40b6de703fc0ac9e36829a9aa191484813b2a5da625b3655f7766ae0fddabbb342fa8646294964460d6a6b6245a1531bb10917f816acdf692b0e495bb68e474dafccc31fcdacdb47e4d9931a211a8952ba066f0c32c2d4b67809051d7f585d069b88b7ca333f6c8a9cd1f0a856ec6b76ecf2eb1bc6a66ef97f890e040d9ad4eff6f2409d5825ae626b5e58ea9b4dffb9a3bf22170969dce47f99738f1b8f9668aa49a9ee9c7f87458f167f4ccd31091593bd55179f4b909cb00851dcf0f282f2244d9435e71ac3b936045ee4a33853634df5f92bc28dae181a73166b89d8263fdcbac1c1dd73cfee2f5e664c0105425984d99301b574178a",
		"7e2b4cde8d0e723a7d693e5d00d85fe9db4c010a7673424fa951e750d726c9eb1b71804b8e800d9d6cf1493f4484150ac3e0586e56220bd44332a357d1a107c658229ffccf3e9e736ba48d7d6164cca34f4bd851557c42ecc40d6c4b5f246cf010f17b666164794ef2800ad07c411481a075ad463a5f86e608a6c85ced805ee757b0e8e34babd0aace97939bcde3c2829d46e30518fb8e4d45f7cd11571c207e7aedbc0f5ee41805264653ad321a92c5d6f99dd14eaa9129874f5b586ff586f78bd67da607e3d2f7a27f032d3f5b59101fb45e55b76d33bb99afa91d4bb946cbda8432490ee669165aee5764c4ea5a7577421037b16f9514f26cf68705e4ac00",
		"6ffe372db1c792631808d6f9076e04dc51343a37b88fddfad930ab30842015bbd445966fd39a5e1256751307b3c4162362ce4faf5e0730f3fb236028a3277c88ac99de6e6655cfe88a23f9a0fa2c3783c0599dc794f4cca23ea8698f6cf7366efa65b1c9c6e684f7c3be93a7b959856b22abbd4e2855258b5210cc2fe8eb68fc5b6adfadf9479418e0b87dc0859ce5e96b43998bd6fbf0222149196dc7eab8bc5a0779f233708b51c3e28f097dd2a2220c449549ff4bb828e28f53f17d70a5afb70a19b350a6eefb0ed09a996ef3fae2de9aff5b33cadacb697f64ffc40f07ca63cf8745a55e7df8a4f73c62a91ed92ced92ab1a6b499be3cd69eb31a57ecd3b",
		"1e41b064db40719ff3ad7099626da706c1e6686218075b6fe661f3f2042c09f1ed74280c88fcb2c31e5ca4bc4af82b9cc8ee28e4f135f6c80ff387170d3c875b9c53e3356075b514d80c21d79d840017a6b99e03450105cd3a543c63763bfb237684a327fe37f05f55742b5a0855499401dfeec4f6bc1c9e67e25f4d6b214755351cc9c49fa23b33bc5d078b056b6a55aa7cff4745301fcc089447c3746a419cb7baf4f60472795e37d8e8bb7b32e5ffb1bf0afb60d81c38145197648c45a4e50c3e8369d799d494a7a5740b9cc8039e9be371c418845f981de4655358e5c465a87f886433cbb079ffbfccb724a4bcf9404d26ec72b751d9053467dde28a9d15",
		"2eb391b65573052b2ae61883f9f437e5c890487e7d76bcedb1c4e648c97960c1dbc9fd8a7b056d44edc093f821e704ff7b0b0e73da9679a5da4e2eb7f8048655833f5a34c46f4862f03d918ef6cfbacd310089008c375d393b0b74cfbce358e53311a8d386d7c7278573ce68268e551e42e45b2698c512101b5d24386ea9bbde7f64c7c3a7b05b524bd2ce97ebad59b7ad962fb9821eefdc1d298364dea94eca8caf3da5697f9ed1df3b0b278750dd4fc68d5438eb4986955fb2e6ff5ea4c80b03c9891918ff0158f299ea61ecfa5491ef7202ebf9eeb543f463cc247c6fb6b56c217acc0987c1b68ed7ae6bc224c2cc0dc9d9ae74c50a3ace78a09b5d655b82",
	}
	xs := GenerateXs(ProofIters, big.NewInt(1234567), N, fixedPub())
	assert.Len(t, xs, ProofIters)
	for i, xi := range xs {
		assert.Equal(t, want[i], hex.EncodeToString(xi.Bytes()), "challenge %d changed", i)
	}
}

// Verify hands GenerateXs a peer-supplied modulus on a goroutine and then
// blocks in a select waiting for it; a modulus that never terminates there
// wedges Verify and leaks the goroutine with it.
func TestProofVerifyTerminatesForAModulusThatIsNotAMultipleOf256Bits(t *testing.T) {
	N := mustParseHex(t, n2049Hex)
	ki := big.NewInt(1234567)
	pub := fixedPub()
	// Small units of Z_N*, enough to get past Verify's per-iteration checks.
	var pf Proof
	for i := range pf {
		pf[i] = big.NewInt(int64(3 + 2*i))
	}
	var res bool
	var err error
	returned := returnsWithin(t, terminationDeadline, func() {
		res, err = pf.Verify(N, ki, pub)
	})
	assert.True(t, returned, "Verify must return rather than block forever")
	assert.NoError(t, err)
	assert.False(t, res)
}

// GenerateKeyPair rejects both P and Q until |P-Q| is within 3 bits of the
// half-modulus width. GetRandomSafePrimesConcurrent sets the top two bits of
// the Germain prime, so all its candidates live in a window of width 2^(h-2)
// with h = modulusBitLen/2, and the loop wants two of them at least 2^(h-4)
// apart. For h <= 8 there is only ever one safe prime in the whole window, so
// P == Q on every draw and the loop cannot terminate at all.
func TestGenerateKeyPairRejectsAModulusItCannotSatisfy(t *testing.T) {
	for _, modulusBitLen := range []int{4, 12, 14, 16, 17} {
		t.Run(strconv.Itoa(modulusBitLen), func(tt *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var err error
			returned := returnsWithin(tt, terminationDeadline, func() {
				_, _, err = GenerateKeyPair(ctx, rand.Reader, modulusBitLen, 1)
			})
			assert.True(tt, returned, "must return rather than retry forever")
			assert.Error(tt, err)
		})
	}
}

// The boundary in the other direction: 18 is the first modulus width whose
// window holds safe primes far enough apart, and it must still be accepted.
func TestGenerateKeyPairAcceptsTheSmallestSatisfiableModulus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), terminationDeadline)
	defer cancel()
	sk, pk, err := GenerateKeyPair(ctx, rand.Reader, 18, 1)
	assert.NoError(t, err)
	assert.NotNil(t, sk)
	assert.NotNil(t, pk)
	assert.Equal(t, 0, new(big.Int).Mul(sk.P, sk.Q).Cmp(pk.N))
}

// A modulus of 1 leaves Encrypt with no unit to blind with — (Z/1Z)* is empty —
// and the m < N test cannot notice, since m = 0 is admissible for N = 1. The
// randomness sampler used to spin on that, so a bad public key parked the
// caller instead of being reported.
func TestEncryptRejectsAModulusWithNoUnits(t *testing.T) {
	for _, N := range []*big.Int{big.NewInt(1), big.NewInt(0)} {
		t.Run(N.String(), func(tt *testing.T) {
			pk := &PublicKey{N: N}
			var err error
			returned := returnsWithin(tt, terminationDeadline, func() {
				_, err = pk.Encrypt(rand.Reader, big.NewInt(0))
			})
			assert.True(tt, returned, "must return rather than sample forever")
			assert.Error(tt, err)
		})
	}
}
