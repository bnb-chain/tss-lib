package tss

type Party interface {
	Start() *Error
	Update(msg Message) (ok bool, err *Error)
	PartyID() *PartyID
	WaitingFor() []*PartyID
	String() string
	ValidateMessage(msg Message) (bool, *Error)
	StoreMessage(msg Message) (bool, *Error)
	Finish()
	Rnd() Round
	Lock()
	Unlock()
}

//func BaseUpdate(p Party, msg Message) (ok bool, err *Error) {
//	if _, err := p.ValidateMessage(msg); err != nil {
//		return false, err
//	}
//	// need this mtx unlock hook, L137 is recursive so cannot use defer
//	r := func(ok bool, err *Error) (bool, *Error) {
//		p.Unlock()
//		return ok, err
//	}
//	p.Lock() // data is written to P state below
//	common.Logger.Debugf("party %s received message: %s", p.PartyID(), msg.String())
//	if p.Rnd() != nil {
//		common.Logger.Debugf("party %s round %d update: %s", p.PartyID(), p.Rnd().RoundNumber(), msg.String())
//	}
//	if ok, err := p.StoreMessage(msg); err != nil || !ok {
//		return r(false, err)
//	}
//	if p.Rnd() != nil {
//		common.Logger.Debugf("party %s: keygen round %d update", p.Rnd().Params().PartyID(), p.Rnd().RoundNumber())
//		if _, err := p.Rnd().Update(); err != nil {
//			return r(false, err)
//		}
//		if p.Rnd().CanProceed() {
//			if p.Rnd() = p.Rnd().NextRound(); p.Rnd() != nil {
//				common.Logger.Infof("party %s: keygen round %d starting", p.Rnd().Params().PartyID(), p.Rnd().RoundNumber())
//				if err := p.Rnd().Start(); err != nil {
//					return r(false, err)
//				}
//			}
//			p.Unlock()           // recursive so can't defer after return
//			return p.Update(msg) // re-run round update or finish)
//		}
//		return r(true, nil)
//	}
//	// finished!
//	common.Logger.Infof("party %s: keygen finished!", p.PartyID())
//	p.Finish()
//	return r(true, nil)
//}
