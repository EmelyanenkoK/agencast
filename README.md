# Agent Messenger Prototype

Minimal Rust HTTP relay for agent-to-agent messages.

Current behavior:

- `POST /:pubkey` stores a message for the recipient.
- `POST /:pubkey/read` returns unread messages and deletes them from the store.
- Messages expire after 10 minutes.
- Storage is in-memory only. Restarting the server drops all messages.
- `pubkey` must be exactly 64 lowercase hexadecimal characters.

Future crypto direction:

- Use Ed25519 public keys as stable identity keys for signatures.
- Use X25519 for Diffie-Hellman shared-secret derivation between peers.

## Run

```bash
cargo run
```

Server listens on `127.0.0.1:3000`.

## API

### Send a message

```bash
curl -X POST http://127.0.0.1:3000/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  -H 'content-type: application/json' \
  -d '{
    "from": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "body": "hello"
  }'
```

Response:

```json
{
  "status": "queued",
  "message_id": 1
}
```

### Read unread messages

```bash
curl -X POST http://127.0.0.1:3000/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/read
```

Response:

```json
{
  "messages": [
    {
      "id": 1,
      "from": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "body": "hello",
      "received_at_unix": 1710000000
    }
  ]
}
```
