# Use Cases

Real-world projects and implementations built on top of `tss-lib`.

---

## MPCIUM — High-Performance MPC Orchestration Layer for tss-lib

**By [Fystack Labs](https://fystack.io/) | [GitHub](https://github.com/fystack/mpcium)**

[MPCIUM](https://github.com/fystack/mpcium) is a high-performance orchestration layer built on top of `tss-lib` that simplifies MPC wallet development. Developers without deep cryptography expertise can deploy and operate MPC nodes, helping boost MPC adoption and reduce the risk of hacks caused by single private key compromise.

### Why MPCIUM

`tss-lib` provides the cryptographic foundation — ECDSA and EdDSA threshold signature protocols. MPCIUM builds on top of it to deliver a complete, production-ready distributed system:

| Layer | tss-lib | MPCIUM |
|---|---|---|
| **Cryptographic protocols** | Keygen, signing, resharing (ECDSA/EdDSA) | Inherits from tss-lib |
| **Messaging** | Not included | NATS JetStream — lightweight, durable pub/sub |
| **Service discovery** | Not included | Consul — dynamic peer registration and health checks |
| **Key share storage** | Not included | BadgerDB with mandatory AES-256 encryption at rest |
| **Peer authentication** | Not included | Ed25519 mutual message verification |
| **Authorization** | Not included | Multi-signature enforcement for operations |
| **Orchestration** | Not included | Session management, quorum detection, fault tolerance |

### Orchestration

Manages the full lifecycle of keygen, signing, and resharing sessions across nodes. Tracks participant readiness via Consul, detects quorum, and only proceeds when the threshold is met. Stale sessions are cleaned up automatically. Concurrent operations are configurable per node.

### Security

Multiple layers of cryptographic protection:

- **Message verification:** All protocol messages are signed (Ed25519) and verified by receivers.
- **ECDH session encryption:** Nodes derive shared symmetric keys via ECDH handshake at startup, creating end-to-end encrypted channels between each peer pair.
- **Encrypted storage:** Key shares stored in BadgerDB with AES-256 encryption. Backups are also encrypted.
- **Authorization:** Optional multi-signature layer requires approval from designated authorizers before operations proceed.
- **No single point of compromise:** The full private key is never assembled on any single node.

### Key Features

- **Threshold signing (t-of-n):** Only `t` out of `n` nodes are required to sign. The full private key is never reconstructed.
- **Byzantine resilience:** Tolerates up to `t-1` node failures while maintaining operations.
- **Multi-chain support:**
  - **ECDSA (secp256k1):** Bitcoin, Ethereum, BNB Chain, Polygon, and all EVM-compatible chains.
  - **EdDSA (Ed25519):** Solana, Polkadot, Cardano, and other Ed25519-based networks.
- **Key resharing:** Rotate key shares across a new set of nodes without changing the public key or wallet identity.
- **HD wallets:** Derive child addresses from a master key using standard BIP32 derivation paths.
- **High concurrency:** Supports concurrent keygen and signing operations with configurable limits per node.
- **Client SDKs:** [Go](https://github.com/fystack/mpcium/tree/main/pkg/client) and [TypeScript](https://github.com/fystack/mpcium-client-ts) client libraries.

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Client SDK (Go / TS)              │
├─────────────────────────────────────────────────────┤
│              Authorization Layer (Ed25519/P256)      │
├─────────┬─────────────┬─────────────┬───────────────┤
│  Node 1 │   Node 2    │   Node 3    │   Node N ...  │
│ ┌─────┐ │  ┌─────┐    │  ┌─────┐    │  ┌─────┐     │
│ │Share│ │  │Share│    │  │Share│    │  │Share│     │
│ └──┬──┘ │  └──┬──┘    │  └──┬──┘    │  └──┬──┘     │
│    │    │     │       │     │       │     │        │
├────┴────┴─────┴───────┴─────┴───────┴─────┴────────┤
│              NATS JetStream (Messaging)             │
├─────────────────────────────────────────────────────┤
│              Consul (Service Discovery)             │
├─────────────────────────────────────────────────────┤
│         tss-lib (Cryptographic Protocols)           │
└─────────────────────────────────────────────────────┘
```

### Getting Started

```bash
git clone https://github.com/fystack/mpcium.git
cd mpcium
```

See the [MPCIUM README](https://github.com/fystack/mpcium#readme) for full installation and configuration instructions.

---

*Want to add your project? Open a PR adding your use case to this file.*
