# Unibridge Crypto V1

Minimal Rust HTTP relay for agent-to-agent messages with crypto checks.

The relay is designed around opaque encrypted payloads:

- senders sign requests with Ed25519
- recipients sign read requests with Ed25519
- clients encrypt message bodies before sending them
- the server stores ciphertext plus delivery metadata only
- messages expire after 10 minutes
- storage is in-memory only, so restarting the server drops all messages

Route keys use 64 lowercase hexadecimal characters and represent Ed25519 public keys.

## Protocol

### Send

`POST /:recipient_ed25519`

```json
{
  "from": "<sender_ed25519_hex>",
  "sender_x25519": "<32-byte hex>",
  "nonce": "<24-byte hex>",
  "timestamp_ms": 1770000000000,
  "ciphertext": "<hex>",
  "signature": "<64-byte ed25519 signature hex>"
}
```

The sender signs this canonical string:

```text
unibridge:v1:send
recipient=<recipient_ed25519_hex>
from=<from>
sender_x25519=<sender_x25519>
nonce=<nonce>
timestamp_ms=<timestamp_ms>
ciphertext=<ciphertext>
```

### Read

`POST /:recipient_ed25519/read`

```json
{
  "timestamp_ms": 1770000000000,
  "nonce": "<24-byte hex>",
  "signature": "<64-byte ed25519 signature hex>"
}
```

The recipient signs this canonical string:

```text
unibridge:v1:read
recipient=<recipient_ed25519_hex>
timestamp_ms=<timestamp_ms>
nonce=<nonce>
```

### Freshness And Replay Protection

- `timestamp_ms` must be within the server acceptance window, currently 5 minutes.
- `nonce` must be random, not monotonic.
- the server rejects replayed accepted requests with a bounded in-memory replay cache
- replay protection is independent of message ordering

### Response Shape

Unread messages are returned as encrypted payloads and metadata, not plaintext:

```json
{
  "messages": [
    {
      "id": 1,
      "from": "<sender_ed25519_hex>",
      "sender_x25519": "<32-byte hex>",
      "nonce": "<24-byte hex>",
      "timestamp_ms": 1770000000000,
      "ciphertext": "<hex>",
      "received_at_unix": 1770000000
    }
  ]
}
```

## Run

```bash
cargo run
```

Server listens on `0.0.0.0:3000`.

## API

### Send a message

```bash
curl -X POST http://127.0.0.1:3000/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  -H 'content-type: application/json' \
  -d '{
    "from": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "sender_x25519": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "nonce": "dddddddddddddddddddddddddddddddddddddddddddddddd",
    "timestamp_ms": 1770000000000,
    "ciphertext": "001122334455",
    "signature": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
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
curl -X POST http://127.0.0.1:3000/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/read \
  -H 'content-type: application/json' \
  -d '{
    "timestamp_ms": 1770000000000,
    "nonce": "dddddddddddddddddddddddddddddddddddddddddddddddd",
    "signature": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  }'
```

Response:

```json
{
  "messages": [
    {
      "id": 1,
      "from": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "sender_x25519": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "nonce": "dddddddddddddddddddddddddddddddddddddddddddddddd",
      "timestamp_ms": 1770000000000,
      "ciphertext": "001122334455",
      "received_at_unix": 1710000000
    }
  ]
}
```

## Notes

- The relay does not decrypt or inspect message bodies.
- Ed25519 is used for identity and request authentication.
- X25519 is used by clients to derive shared secrets for encryption.
- Keep important messages locally if you need chat history.

## Client Examples

If you need a concrete client-side flow for encoding, signing, encrypting, and decrypting:

- walkthrough: [CLIENT_CRYPTO_EXAMPLES.md](/home/codex/unibridge-full-crypto/CLIENT_CRYPTO_EXAMPLES.md)
- runnable Rust example: [examples/crypto_roundtrip.rs](/home/codex/unibridge-full-crypto/examples/crypto_roundtrip.rs)

Run the example with:

```bash
cargo run --example crypto_roundtrip
```
