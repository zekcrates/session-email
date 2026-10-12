# Session Mail

Session Mail is a small full-stack experiment in private, email-like messaging.

It combines end-to-end encryption, sender signatures, and onion routing. The goal is to demonstrate how a message can travel through multiple nodes without exposing its contents to those nodes.

This project is inspired by the [Session Protocol](https://arxiv.org/abs/2002.04609).

## What it does

- Generates a local Ed25519 identity in the browser.
- Uses the public key as the account ID.
- Signs messages so the recipient can verify the sender.
- Encrypts messages so only the recipient can read them.
- Sends messages through three onion-routed nodes.
- Provides a simple inbox and sent-mail interface.

## How a message works

1. Alice writes a message for Bob.
2. The browser signs the message with Alice's private key.
3. The browser encrypts the signed message with Bob's public key.
4. The browser wraps the request in three encrypted onion layers.
5. The request travels through Node A, Node B, and Node C.
6. Node C stores only the encrypted payload.
7. Bob fetches the message and decrypts and verifies it in the browser.

The nodes can forward and store messages, but they do not have the recipient's private key.

## Project structure

```text
src/
  main.go              Starts the three nodes and circuit config server
  crypto/              Key generation, encryption, and signatures
  message/             Message serialization and padding
  node/                HTTP nodes, onion routing, and swarm helpers

client/
  src/App.jsx          Mail UI and send/fetch flows
  src/lib/crypto.js    Browser crypto and onion-packet creation

tests/                 Go unit and end-to-end tests
ARCHITECTURE.md        Simple system architecture notes
```

## Run locally

### 1. Start the Go backend

From the project root:

```sh
go run ./src
```

This starts:

- Node A at `http://localhost:8001`
- Node B at `http://localhost:8002`
- Node C at `http://localhost:8003`
- Circuit config at `http://localhost:8080/api/circuit`

### 2. Start the React client

In another terminal:

```sh
cd client
npm install
npm run dev
```

Open `http://localhost:5173` in two browser tabs. Generate an identity in each tab, copy one account ID into the other tab, and send a message.

## Run tests

```sh
go test ./tests/ -v
```

## Security model

- Ed25519 is used for identities and signatures.
- X25519/NaCl box encryption is used for message and onion-layer encryption.
- Private keys stay in the browser's local storage and are not sent to the nodes.
- Mailbox reads require a signature over the recipient account ID and a timestamp.
- Sender signatures are verified after decryption.

## Current limitations

This is a learning project and not production-ready messaging software.

- Node storage is in memory and disappears when the backend stops.
- The demo uses a fixed three-node local circuit.
- Timestamp freshness is not currently enforced by the server.
- The browser stores private keys in `localStorage`; this is convenient for the demo but not suitable for a hardened wallet.
- There is no spam protection, account recovery, persistence, or production deployment setup.

## Screenshots

![Inbox](assets/Screenshot%202026-09-11%20093340.png)

![Sent](assets/Screenshot%202026-09-11%20093313.png)
