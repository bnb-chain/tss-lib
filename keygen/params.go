package keygen

type (
	KGParameters struct {
		partyCount      int
		threshold       int
		localShareCount int // partyCount - 1
	}
)

// Exported, used in `tss` client
func NewKGParameters(partyCount int, threshold int) *KGParameters {
	return &KGParameters{
		partyCount:      partyCount,
		threshold:       threshold,
		localShareCount: partyCount - 1,
	}
}

func (params KGParameters) PartyCount() int {
	return params.partyCount
}

func (params KGParameters) Threshold() int {
	return params.threshold
}

func (params KGParameters) LocalShareCount() int {
	return params.localShareCount
}
