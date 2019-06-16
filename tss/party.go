package tss

type Party interface {
	Start() *Error
	Update(msg Message) (ok bool, err *Error)
	WaitingFor() []*PartyID
	String() string
}
