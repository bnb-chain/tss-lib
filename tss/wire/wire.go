package wire

import (
	"github.com/golang/protobuf/proto"

	"github.com/binance-chain/tss-lib/ecdsa/keygen"
)

const (
	ProtoNamePrefix = "github.com/binance-chain/tss-lib/"
)

func init() {
	proto.RegisterType((*keygen.KGRound1Message)(nil), "tss/ecdsa/keygen/KGRound1Message")
	proto.RegisterType((*keygen.KGRound2Message1)(nil), "tss/ecdsa/keygen/KGRound2Message1")
	proto.RegisterType((*keygen.KGRound2Message2)(nil), "tss/ecdsa/keygen/KGRound2Message2")
	proto.RegisterType((*keygen.KGRound3Message)(nil), "tss/ecdsa/keygen/KGRound3Message")
}
