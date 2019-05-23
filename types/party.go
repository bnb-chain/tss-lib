package types

type (
	Party interface {
		IsLocal() bool
		CurrentRound() int
		Update(msg Message) (success bool, err error)
	}
)
