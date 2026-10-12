# Session Mail Architecture

This document gives a simple overview of how Session Mail sends and receives messages.

## High-level flow

```text
┌─────────────────────┐
│  React web client   │
│  keys + encryption  │
└──────────┬──────────┘
           │ encrypted onion packet
           ▼
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│ Node A :8001        │ ──▶ │ Node B :8002        │ ──▶ │ Node C :8003        │
│ removes layer 1     │     │ removes layer 2     │     │ removes layer 3     │
└─────────────────────┘     └─────────────────────┘     └──────────┬──────────┘
                                                                    │
                                                                    ▼
                                                           encrypted mailbox
```

The browser builds the complete route before sending anything. Each node can decrypt only its own layer and learns only the next hop.

## Sending a message

1. The sender creates a message containing the sender ID, recipient ID, subject, body, and timestamp.
2. The message is padded and signed with the sender's Ed25519 private key.
3. The signed message is encrypted with the recipient's public key.
4. The browser creates the final `POST /messages` request for Node C.
5. That request is wrapped in an encryption layer for Node C, then Node B, then Node A.
6. The browser sends the outer packet to Node A.
7. Each node decrypts one layer and forwards the remaining packet.
8. Node C receives the final internal request and stores the encrypted message.

## Receiving a message

1. The recipient signs a challenge containing their account ID and the current timestamp.
2. The client requests messages from Node C with `X-Timestamp` and `X-Signature` headers.
3. Node C verifies that the request was signed by the owner of the mailbox.
4. The browser decrypts each message using the recipient's private key.
5. The browser extracts the sender public key and verifies the sender's signature.
6. Verified messages are displayed in the inbox.

## Main components

### Browser client

The React app handles identity creation, message composition, encryption, decryption, signature verification, and the mail UI.

Important file: `client/src/lib/crypto.js`

### Go nodes

Each node exposes:

- `POST /onion` for receiving and forwarding onion packets.
- `POST /messages` for storing a final encrypted message.
- `GET /messages` for authenticated mailbox reads.

Important files:

- `src/node/server.go`
- `src/node/onion.go`

### Cryptography

- Ed25519: identity keys and message signatures.
- X25519 conversion: derives encryption-compatible keys from Ed25519 keys.
- NaCl box: authenticated public-key encryption for messages and onion layers.

Important files:

- `src/crypto/identity.go`
- `src/crypto/encryption.go`
- `src/crypto/sign.go`

## Trust boundaries

```text
Sender browser ── encrypts ──▶ recipient browser
       │                              ▲
       │ onion-routed packet           │ private key
       ▼                              │
  A ──▶ B ──▶ C ── stores ciphertext ─┘
```

The nodes are transport and storage infrastructure. They should not be able to read the message body or forge a valid sender signature.

## Runtime notes

- The demo starts all three nodes from `src/main.go`.
- Node storage is currently in memory.
- The frontend discovers the local circuit through `/api/circuit`.
- The `src/node/swarm.go` package contains additional swarm helpers and tests, but the current browser flow uses the fixed three-node circuit directly.
