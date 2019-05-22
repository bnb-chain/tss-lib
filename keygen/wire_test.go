package keygen_test

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"tss-lib/crypto/commitments"
	"tss-lib/crypto/paillier"
	"tss-lib/keygen"
	"tss-lib/types"
)

func newRandomPartyID() *types.PartyID {
	id      := string(rand.Int())
	moniker := string(rand.Int())
	return types.NewPartyID(id, moniker)
}

func TestEncodeDecodeMsg(t *testing.T) {
	type args struct {
		data []byte
	}

	to   := newRandomPartyID()
	from := newRandomPartyID()
	cmt  := new(commitments.HashCommitment)
	pk   := new(paillier.PublicKey)
	msg1 := keygen.KGMessage(keygen.NewKGPhase1CommitMessage(to, from, *cmt, pk))
	emsg1, err := keygen.EncodeMsg(msg1)
	assert.NoError(t, err, "encode should not fail")

	tests := []struct {
		name    string
		args    args
		want    keygen.KGMessage
		wantErr bool
	}{
		{
			name: "happy path",
			args: args{emsg1},
			want: msg1,
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
