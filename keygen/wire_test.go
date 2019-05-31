package keygen_test

import (
	rsa2 "crypto/rsa"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/math"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/keygen"
	"github.com/binance-chain/tss-lib/types"
)

func newRandomPartyID() *types.PartyID {
	id := fmt.Sprintf("%d", math.MustGetRandomInt(64))
	moniker := fmt.Sprintf("%d", math.MustGetRandomInt(64))
	return types.NewPartyID(id, moniker)
}

func TestEncodeDecodeMsg(t *testing.T) {
	type args struct {
		data []byte
	}

	from := newRandomPartyID()
	cmt := new(commitments.HashCommitment)
	pk := new(paillier.PublicKey)
	pf := new(paillier.Proof)
	rsa := new(rsa2.PublicKey)
	msg1 := types.Message(keygen.NewKGRound1CommitMessage(from, *cmt, pk, pf, rsa))
	emsg1, err := keygen.EncodeMsg(msg1)
	assert.NoError(t, err, "encode should not fail")

	tests := []struct {
		name    string
		args    args
		want    types.Message
		wantErr bool
	}{
		{
			name:    "happy path",
			args:    args{emsg1},
			want:    msg1,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keygen.DecodeMsg(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeMsg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecodeMsg() = %v, want %v", got, tt.want)
			}
		})
	}
}
