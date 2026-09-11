# Session Mail

A full-stack implementation of the [Session Protocol](https://arxiv.org/abs/2002.04609) — end-to-end encrypted email with onion routing.

## Screenshots

**Inbox** — received message with verified sender signature and encryption badge

![Inbox](assets/Screenshot%202026-09-11%20093340.png)

**Sent** — sent message view with recipient info

![Sent](assets/Screenshot%202026-09-11%20093313.png)

## Architecture

```
Frontend (React/Vite/Tailwind)
    ↓ builds onion (3 layers, NaCl box per hop)
Node A (:8001)  →  Node B (:8002)  →  Node C (:8003)
    ↑ peels layer     ↑ peels layer     ↑ stores message
```

- **Identity**: Ed25519 keypairs, Account ID = `"05" + hex(pubKey)`
- **Message encryption**: NaCl sealed box (ephemeral X25519 + recipient's key)
- **Onion routing**: 3 hops, each encrypted.no node sees more than the next hop
- **Signatures**: Ed25519 detached signatures, verified on fetch
- **Auth**: Signed timestamp challenge (`X-Timestamp` + `X-Signature` headers)

## Running

### Go server (starts 3 nodes + config endpoint)

```sh
go run ./src
```

### React client

```sh
cd client
npm install
npm run dev
```

Open `http://localhost:5173` in two browser tabs, generate identities, and send messages through the onion network.

## Testing

```sh
go test ./tests/ -v
```

