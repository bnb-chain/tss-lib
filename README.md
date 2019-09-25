Multi-party ECDSA
=====================================

This project is a Go implementation of {t,n}-threshold ECDSA (elliptic curve digital signature algorithm) based on GG18.

This library includes three protocols:

* Key Generation for creating secret shares ("keygen").
* Signing for using the secret shares to generate a signature ("signing").
* Dynamic Groups to change the group of participants while keeping the secret ("regroup").

ECDSA is used extensively for crypto-currencies such as Bitcoin, Ethereum (secp256k1 curve), NEO (NIST P-256 curve) and much more. 
This library can be used to create MultiSig and ThresholdSig crypto wallets.

Usage
------------------
You should start by creating an instance of a `LocalParty` and giving it the initialization arguments that it needs.

The `LocalParty` that you use should be from the `keygen`, `signing` or `regroup` package, depending on what you want to do.

```go
thisParty := tss.NewPartyID(id, moniker, uniqueKey)
ctx := tss.NewPeerContext(tss.SortPartyIDs(allParties))
params := tss.NewParameters(p2pCtx, thisParty, len(allParties), threshold)
party := keygen.NewLocalParty(params, outCh, endCh)
go func() {
    err := party.Start()
    // handle err ...
}()
```

In this example, the `outCh` will receive outgoing messages from this party, and the `endCh` will receive a message when the protocol is complete.

During the protocol, you should provide the party with updates received from other parties over the network (implementing the network transport is left to you):

A `Party` has two thread-safe methods on it for receiving updates:
```go
// The main entry point when updating a party's state from the wire
UpdateFromBytes(wireBytes []byte, from *tss.PartyID, to []*tss.PartyID) (ok bool, err *tss.Error)
// You may use this entry point to update a party's state when running locally or in tests
Update(msg tss.ParsedMessage) (ok bool, err *tss.Error)
```

And a `tss.Message` has the following two methods for converting messages to data for the wire:
```go
// Returns the encoded bytes to send over the wire
WireBytes() ([]byte, error)
// Returns the protobuf message struct to send over the wire
WireMsg() *protob.Message
```

In a typical use case, it is expected that a transport implementation will **consume** message bytes via the `out` channel of the local `Party`, send them to the destination(s) specified in the result of `msg.GetTo()`, and **pass** them to `UpdateFromBytes` on the receiving end.

This way, there is no need to deal with Marshal/Unmarshalling Protocol Buffers to implement a transport.

Please note that such a transport should employ suitable end-to-end encryption to ensure that a party can only read the messages intended for it.

Resources
-------------------

GG18: https://eprint.iacr.org/2019/114.pdf
