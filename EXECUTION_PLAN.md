# Unibridge Crypto V1 Execution Plan

## Goal

Replace the current plaintext prototype with a crypto-checked relay that:

- uses Ed25519 public keys as stable identities
- authenticates sends and reads with signatures
- stores only encrypted message payloads
- rejects stale and replayed requests
- preserves the current relay behavior: in-memory queue, TTL expiry, read-once delivery

## Agreed Protocol Shape

### Identity

- The route key remains `/:pubkey` and `/:pubkey/read`.
- `pubkey` is the recipient's Ed25519 public key encoded as 64 lowercase hex characters.
- `from` is the sender's Ed25519 public key encoded the same way.

### Send Request

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

### Read Request

`POST /:recipient_ed25519/read`

```json
{
  "timestamp_ms": 1770000000000,
  "nonce": "<24-byte hex>",
  "signature": "<64-byte ed25519 signature hex>"
}
```

### Read Response

The server returns encrypted messages and metadata, not plaintext:

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

## Security Rules

### Signatures

Send requests are signed by `from` over this exact canonical string:

```text
unibridge:v1:send
recipient=<recipient_ed25519_hex>
from=<from>
sender_x25519=<sender_x25519>
nonce=<nonce>
timestamp_ms=<timestamp_ms>
ciphertext=<ciphertext>
```

Read requests are signed by the recipient key over this exact canonical string:

```text
unibridge:v1:read
recipient=<recipient_ed25519_hex>
timestamp_ms=<timestamp_ms>
nonce=<nonce>
```

### Encryption

- Clients use X25519 to derive a shared secret.
- Clients encrypt the plaintext payload with XChaCha20-Poly1305.
- The relay does not decrypt messages.
- The relay stores only ciphertext and metadata required for delivery and verification.

### Freshness And Replay Protection

- `timestamp_ms` must be within a configured acceptance window of server time.
- `nonce` must be random, not monotonic.
- The server keeps a bounded replay cache for accepted requests only.
- Replay cache key:
  - send: digest or tuple of `(from, timestamp_ms, nonce, signature)`
  - read: digest or tuple of `(recipient, timestamp_ms, nonce, signature)`
- Replay entries expire when the acceptance window expires.

This avoids ordering bugs and supports concurrent sends safely.

## Implementation Steps

### 1. Add Dependencies

Update `Cargo.toml` with the crypto and utility crates needed for:

- Ed25519 signature verification
- X25519 key handling helpers if needed for validation
- XChaCha20-Poly1305 message format support if any server-side parsing is required
- hex decoding
- time handling
- hashing for replay-cache keys

Likely crates:

- `ed25519-dalek`
- `hex`
- `sha2`
- `rand` if local test vectors or helper generation is needed

The relay should not require recipient private keys, since it only verifies/authenticates and stores opaque ciphertext.

### 2. Replace Request And Storage Models

Replace the current plaintext request/response structs in `src/main.rs` with:

- crypto send request
- crypto read request
- encrypted message response view
- stored encrypted message model

Remove plaintext `body` from storage and responses.

### 3. Add Validation Helpers

Implement helpers for:

- 64-char lowercase hex Ed25519 public key validation
- 32-byte hex X25519 public key validation
- 24-byte hex nonce validation
- 64-byte hex Ed25519 signature validation
- ciphertext hex validation
- canonical signing string generation
- timestamp freshness checks
- replay-cache key derivation

### 4. Add Replay Cache State

Extend application state with replay protection:

- in-memory replay cache for recently accepted send requests
- in-memory replay cache for recently accepted read requests
- cleanup logic that expires replay entries on the same periodic cleanup loop

Replay protection must be independent of message queue ordering.

### 5. Rewrite Send Endpoint

`POST /:pubkey` should:

1. validate recipient key and request field formats
2. validate timestamp window
3. build the canonical signed payload
4. verify the Ed25519 signature using `from`
5. reject duplicate accepted requests via replay cache
6. store encrypted message metadata and ciphertext
7. return queued status and message id

The server should log metadata only and must not log sensitive ciphertext in full.

### 6. Rewrite Read Endpoint

`POST /:pubkey/read` should:

1. require JSON body with signed read request
2. validate recipient key and request field formats
3. validate timestamp window
4. build the canonical signed payload
5. verify the Ed25519 signature using the recipient key from the path
6. reject duplicate accepted read requests via replay cache
7. return unread encrypted messages and delete them from the queue

### 7. Preserve Queue Semantics

Keep the existing non-crypto service behavior unless explicitly changed:

- in-memory only
- 10 minute message TTL
- periodic cleanup
- read-once delivery
- monotonically increasing server-side message IDs

### 8. Update Public Documentation

Update:

- `README.md`
- `skill/unibridge/SKILL.md`

Document:

- new send/read request shapes
- signature inputs
- freshness and replay requirements
- that the server stores opaque ciphertext only
- example client flow for key usage and message exchange

### 9. Add Tests

Add tests for:

- valid signed send accepted
- invalid signature rejected
- malformed hex rejected
- stale timestamp rejected
- duplicate send rejected
- valid signed read accepted
- duplicate read rejected
- expired messages dropped

Where practical, include deterministic test vectors for canonical signing strings.

## Suggested Configuration Constants

- message TTL: `10 minutes`
- cleanup interval: `30 seconds`
- freshness window: `5 minutes`
- nonce size: `24 bytes`
- recipient and sender identity key size: `32 bytes`
- signature size: `64 bytes`

## Non-Goals For This Revision

- persistent storage
- account registration
- server-side decryption
- ordered nonces
- compatibility shim for the plaintext API unless explicitly requested later

## Deliverables

- updated Rust service implementing crypto-checked send/read flows
- replay protection with bounded in-memory state
- updated README and skill documentation
- test coverage for verification and rejection paths
