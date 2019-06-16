package keygen_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common/random"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	. "github.com/binance-chain/tss-lib/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

func TestEncodeDecodeMsg(t *testing.T) {
	// TODO fix broken wire test
	t.Skip("breaks due to pointer use in LocalPartySaveData, will fix later")

	type args struct {
		data []byte
	}

	from := tss.GenerateTestPartyIDs(1)[0]
	cmt := new(commitments.HashCommitment)
	pk := new(paillier.PublicKey)
	N := random.GetRandomPositiveInt(tss.EC().Params().N)
	msg1 := tss.Message(NewKGRound1CommitMessage(from, *cmt, pk, N, N, N))
	emsg1, err := EncodeMsg(msg1)
	assert.NoError(t, err, "encode should not fail")

	tests := []struct {
		name    string
		args    args
		want    tss.Message
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
			got, err := DecodeMsg(tt.args.data)
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
