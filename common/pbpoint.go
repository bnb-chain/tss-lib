// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

func (x *ECPoint) ValidateBasic() bool {
	return x != nil && NonEmptyBytes(x.GetX()) && NonEmptyBytes(x.GetY())
}
