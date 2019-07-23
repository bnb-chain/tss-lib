package tss

import (
	"fmt"
)

type (
	Message interface {
		GetTo() []*PartyID
		GetFrom() *PartyID
		GetType() string
		IsToOldCommittee() bool
		ValidateBasic() bool
		String() string
	}

	MessageMetadata struct {
		// if `To` is `nil`, the message should be broadcast to all parties.
		To             []*PartyID
		From           *PartyID
		MsgType        string
		ToOldCommittee bool // just `true` in DGRound2NewCommitteeACKMessage (regroup)
	}
)

func (mm MessageMetadata) GetTo() []*PartyID {
	return mm.To
}

func (mm MessageMetadata) GetFrom() *PartyID {
	return mm.From
}

func (mm MessageMetadata) GetType() string {
	return mm.MsgType
}

func (mm MessageMetadata) IsToOldCommittee() bool {
	return mm.ToOldCommittee
}

func (mm MessageMetadata) String() string {
	toStr := "all"
	if mm.To != nil {
		toStr = fmt.Sprintf("%v", mm.To)
	}
	extraStr := ""
	if mm.ToOldCommittee {
		extraStr = " (To Old Committee)"
	}
	return fmt.Sprintf("Type: %s, From: %s, To: %s%s", mm.MsgType, mm.From.String(), toStr, extraStr)
}
