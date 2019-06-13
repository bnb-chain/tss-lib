package tss

type Party interface {
	String() string
	Start() *Error
	Update(msg Message) (ok bool, err *Error)
	WaitingFor() []*PartyID
}
