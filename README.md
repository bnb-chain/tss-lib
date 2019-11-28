# Multi-Party Threshold Signature Scheme
[![MIT licensed][1]][2] [![GoDoc][3]][4] [![Go Report Card][5]][6]

[1]: https://img.shields.io/badge/license-MIT-blue.svg
[2]: LICENSE
[3]: https://godoc.org/github.com/binance-chain/tss-lib?status.svg
[4]: https://godoc.org/github.com/binance-chain/tss-lib
[5]: https://goreportcard.com/badge/github.com/binance-chain/tss-lib
[6]: https://goreportcard.com/report/github.com/binance-chain/tss-lib

Permissively MIT Licensed.

Note! This is a library for developers. You may find a TSS tool that you can use with the Binance Chain CLI [here](https://docs.binance.org/tss.html).

## Introduction
This is an implementation of multi-party {t,n}-threshold ECDSA (elliptic curve digital signatures) based on Gennaro and Goldfeder CCS 2018 [\[1\]](#references)

This library includes three protocols:

* Key Generation for creating secret shares with no trusted dealer ("keygen").
* Signing for using the secret shares to generate a signature ("signing").
* Dynamic Groups to change the group of participants while keeping the secret ("resharing").

⚠️ Do not miss [these important notes](#how-to-use-this-securely) on implementing this library securely

## Rationale
ECDSA is used extensively for crypto-currencies such as Bitcoin, Ethereum (secp256k1 curve), NEO (NIST P-256 curve) and many more. 
For such currencies this technique may be used to create crypto wallets where multiple parties must collaborate to sign transactions. See [MultiSig Use Cases](https://en.bitcoin.it/wiki/Multisignature#Multisignature_Applications)

One secret share per key/address is stored locally by each participant and these are kept safe by the protocol – they are never revealed to others at any time. Moreover, there is no trusted dealer of the shares.

In contrast to MultiSig solutions, transactions produced by TSS preserve the privacy of the signers by not revealing which `t+1` participants were involved in their signing.

There is also a performance bonus in that blockchain nodes may check the validity of a signature without any extra MultiSig logic or processing.

## Usage
You should start by creating an instance of a `LocalParty` and giving it the arguments that it needs.

The `LocalParty` that you use should be from the `keygen`, `signing` or `resharing` package depending on what you want to do.

### Setup
```go
// When using the keygen party it is recommended that you pre-compute the "safe primes" and Paillier secret beforehand because this can take some time.
// This code will generate those parameters using a concurrency limit equal to the number of available CPU cores.
preParams, _ := keygen.GeneratePreParams(1 * time.Minute)

// Create a `*PartyID` for each participating peer on the network (you should call `tss.NewPartyID` for each one)
parties := tss.SortPartyIDs(getParticipantPartyIDs())

// Set up the parameters
// Note: The `id` and `moniker` fields are for convenience to allow you to easily track participants.
// The `id` should be a unique string representing this party in the network and `moniker` can be anything (even left blank).
// The `uniqueKey` is a unique identifying key for this peer (such as its p2p public key) as a big.Int.
thisParty := tss.NewPartyID(id, moniker, uniqueKey)
ctx := tss.NewPeerContext(parties)
params := tss.NewParameters(ctx, thisParty, len(parties), threshold)

// You should keep a local mapping of `id` strings to `*PartyID` instances so that an incoming message can have its origin party's `*PartyID` recovered for passing to `UpdateFromBytes` (see below)
partyIDMap := make(map[string]*PartyID)
for _, id := range parties {
    partyIDMap[id.Id] = id
}
```

### Keygen
Use the `keygen.LocalParty` for the keygen protocol. The save data you receive through the `endCh` upon completion of the protocol should be persisted to secure storage.

```go
party := keygen.NewLocalParty(params, outCh, endCh, preParams) // Omit the last arg to compute the pre-params in round 1
go func() {
    err := party.Start()
    // handle err ...
}()
```

### Signing
Use the `signing.LocalParty` for signing and provide it with a `message` to sign. It requires the key data obtained from the keygen protocol. The signature will be sent through the `endCh` once completed.

Please note that `t+1` signers are required to sign a message and for optimal usage no more than this should be involved. Each signer should have the same view of who the `t+1` signers are.

```go
party := signing.NewLocalParty(message, params, ourKeyData, outCh, endCh)
go func() {
    err := party.Start()
    // handle err ...
}()
```

### Re-Sharing
Use the `resharing.LocalParty` to re-distribute the secret shares. The save data received through the `endCh` should overwrite the existing key data in storage, or write new data if the party is receiving a new share.

Please note that `ReSharingParameters` is used to give this Party more context about the re-sharing that should be carried out.

```go
party := resharing.NewLocalParty(params, ourKeyData, outCh, endCh)
go func() {
    err := party.Start()
    // handle err ...
}()
```

⚠️ During re-sharing the key data may be modified during the rounds. Do not ever overwrite any data saved on disk until the final struct has been received through the `end` channel.

## Messaging
In these examples the `outCh` will collect outgoing messages from the party and the `endCh` will receive save data or a signature when the protocol is complete.

During the protocol you should provide the party with updates received from other participating parties on the network.

A `Party` has two thread-safe methods on it for receiving updates.
```go
// The main entry point when updating a party's state from the wire
UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (ok bool, err *tss.Error)
// You may use this entry point to update a party's state when running locally or in tests
Update(msg tss.ParsedMessage) (ok bool, err *tss.Error)
```

And a `tss.Message` has the following two methods for converting messages to data for the wire:
```go
// Returns the encoded message bytes to send over the wire along with routing information
WireBytes() ([]byte, *tss.MessageRouting, error)
// Returns the protobuf wrapper message struct, used only in some exceptional scenarios (i.e. mobile apps)
WireMsg() *tss.MessageWrapper
```

In a typical use case, it is expected that a transport implementation will consume message bytes via the `out` channel of the local `Party`, send them to the destination(s) specified in the result of `msg.GetTo()`, and pass them to `UpdateFromBytes` on the receiving end.

This way there is no need to deal with Marshal/Unmarshalling Protocol Buffers to implement a transport.

## How to use this securely

⚠️ This section is important. Be sure to read it!

The transport for messaging is left to the application layer and is not provided by this library. Each one of the following paragraphs should be read and followed carefully as it is crucial that you implement a secure transport to ensure safety of the protocol.

When you build a transport, it should offer a broadcast channel as well as point-to-point channels connecting every pair of parties. Your transport should also employ suitable end-to-end encryption (TLS with an [AEAD cipher](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)) is recommended) between parties to ensure that a party can only read the messages sent to it.

Within your transport, each message should be wrapped with a **session ID** that is unique to a single run of the keygen, signing or re-sharing rounds. This session ID should be agreed upon out-of-band and known only by the participating parties before the rounds begin. Upon receiving any message, your program should make sure that the received session ID matches the one that was agreed upon at the start.

Additionally, there should be a mechanism in your transport to allow for "reliable broadcasts", meaning parties can broadcast a message to other parties such that it's guaranteed that each one receives the same message. There are several examples of algorithms online that do this by sharing and comparing hashes of received messages.

Timeouts and errors should be handled by your application. The method `WaitingFor` may be called on a `Party` to get the set of other parties that it is still waiting for messages from. You may also get the set of culprit parties that caused an error from a `*tss.Error`.

## Security Audit
A full review of this library was carried out by Kudelski Security and their final report was made available in October, 2019. A copy of this report [`audit-binance-tss-lib-final-20191018.pdf`](https://github.com/binance-chain/tss-lib/releases/download/v1.0.0/audit-binance-tss-lib-final-20191018.pdf) may be found in the v1.0.0 release notes of this repository.

## References
\[1\] https://eprint.iacr.org/2019/114.pdf

