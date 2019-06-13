package tss

type Round interface {
	Params() *Parameters
	Start() *Error
	Update() (bool, *Error)
	RoundNumber() int
	CanAccept(msg Message) bool
	CanProceed() bool
	NextRound() Round
	WaitingFor() []*PartyID
	WrapError(err error, culprits ...*PartyID) *Error
}
