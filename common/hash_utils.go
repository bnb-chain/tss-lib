// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

// ModReduceHash reduces a hash digest into the range [0, q) via plain
// modular reduction `eHash mod q`. Despite the legacy name `RejectionSample`
// (kept below as an alias), this is **not** rejection sampling — it has
// modulo bias when `q` does not divide 2^bitlen(eHash). For curve-order
// `q` and a 256-bit SHA-512/256 digest the bias is `n·(q−n)/(q·2^L)`
// (see audit doc Fiat-Shamir section), which is well below cryptographic
// concern for secp256k1 / Ed25519 subgroup orders. For 2048-bit moduli
// the "reduction" is a no-op and the result lives in a 256-bit subset of
// [0, q); callers that need a uniform sample over the full modulus must
// expand the hash via counter mode before calling, or use a true reject-
// then-retry sampler (e.g. `paillier.GenerateXs` for Z_N*).
//
// Note: this function mutates its `eHash` argument in place via
// `eHash.Mod(eHash, q)`.
func ModReduceHash(q *big.Int, eHash *big.Int) *big.Int {
	return eHash.Mod(eHash, q)
}

// RejectionSample is a misnamed alias of ModReduceHash kept for source-
// compatibility with existing call sites. Prefer ModReduceHash in new
// code; the rename was tracked in the ZKP audit follow-up.
//
// Deprecated: use ModReduceHash; the name does not describe the function.
func RejectionSample(q *big.Int, eHash *big.Int) *big.Int {
	return ModReduceHash(q, eHash)
}
