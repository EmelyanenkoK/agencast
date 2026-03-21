# Agencast P-256 Execution Plan

## Goal

Use one P-256 keypair per agent for:

- ECDSA request signatures
- ECDH shared-secret derivation

Keep the relay behavior the same:

- in-memory queue
- read-once delivery
- 10 minute TTL
- freshness and replay checks
- ciphertext-only storage

## Protocol

### Route Key

- `/:pubkey`, `/:pubkey/read`, and draft `/:pubkey/ws`
- `pubkey` is a compressed P-256 SEC1 public key encoded as 66 lowercase hex chars

### Send Request

```json
{
  "from": "<sender_p256_public_hex>",
  "nonce": "<12-byte hex>",
  "timestamp_ms": 1770000000000,
  "ciphertext": "<hex>",
  "signature": "<64-byte p256 ecdsa signature hex>"
}
```

### Read Request

```json
{
  "timestamp_ms": 1770000000000,
  "nonce": "<12-byte hex>",
  "signature": "<64-byte p256 ecdsa signature hex>"
}
```

### Canonical Send String

```text
agencast:v1:send
recipient=<recipient_p256_public_hex>
from=<sender_p256_public_hex>
nonce=<nonce_hex>
timestamp_ms=<timestamp_ms>
ciphertext=<ciphertext_hex>
```

### Canonical Read String

```text
agencast:v1:read
recipient=<recipient_p256_public_hex>
timestamp_ms=<timestamp_ms>
nonce=<nonce_hex>
```

### Draft Canonical WebSocket Auth String

```text
agencast:v1:ws:open
recipient=<recipient_p256_public_hex>
timestamp_ms=<timestamp_ms>
nonce=<nonce_hex>
```

## Encryption Guidance

Recommended client flow:

- derive ECDH shared secret using the same P-256 keypair
- derive a 32-byte AEAD key with `SHA-256(shared_secret)`
- encrypt with AES-256-GCM
- use a fresh random 12-byte nonce

## WebSocket V1 Scope

The first WebSocket version is receive-only.

- keep `POST /:pubkey` as the only send path
- add `GET /:pubkey/ws` as an authenticated push-read channel
- do not support sending encrypted messages over WebSocket in v1
- do not require client acknowledgements in v1

This keeps the protocol small and reuses the current HTTP send path and message shape.

## WebSocket Protocol

### Route

- `GET /:recipient_p256_public_hex/ws`

### Opening Flow

1. Client opens a WebSocket connection to `/:pubkey/ws`
2. Client must send an `auth` JSON message immediately after connect
3. Server verifies recipient key ownership using the existing P-256 signature model
4. Server verifies freshness and replay protection
5. On success, server sends `ready`
6. Server flushes queued unread messages for that recipient
7. Server pushes newly queued messages in real time until disconnect

### Client Auth Message

```json
{
  "type": "auth",
  "timestamp_ms": 1770000000000,
  "nonce": "<12-byte nonce hex>",
  "signature": "<64-byte p256 ecdsa signature hex>"
}
```

The signature must be computed over the canonical `agencast:v1:ws:open` string using the recipient private key.

### Server Ready Message

```json
{
  "type": "ready",
  "recipient": "<recipient_p256_public_hex>"
}
```

### Server Message Event

```json
{
  "type": "message",
  "message": {
    "id": 1,
    "from": "<sender_p256_public_hex>",
    "nonce": "<12-byte hex>",
    "timestamp_ms": 1770000000000,
    "ciphertext": "<hex>",
    "received_at_unix": 1770000000
  }
}
```

### Server Error Event

```json
{
  "type": "error",
  "error": "unauthorized: invalid ws auth signature",
  "docs": "/"
}
```

After sending an `error` event for authentication or protocol failure, the server closes the connection.

## Delivery Semantics

- WebSocket delivery is authenticated recipient read access, equivalent in authority to `POST /:pubkey/read`
- immediately after successful auth, the server flushes queued unread messages for that recipient
- messages delivered through the authenticated WebSocket are consumed and removed from the in-memory queue
- when no WebSocket is connected, `POST /:pubkey/read` remains available
- if WebSocket read and HTTP read race, the first successful delivery path consumes the message
- v1 allows only one active authenticated WebSocket per recipient
- if a second authenticated socket for the same recipient appears, the server closes the older connection

## Security And Operational Rules

- require a valid `auth` message before any message delivery
- use the same freshness window as HTTP read
- add a dedicated WebSocket replay cache keyed by canonical auth string and signature
- close idle unauthenticated sockets quickly
- send periodic ping frames and rely on normal pong handling
- clean up per-recipient connection state on disconnect
- do not change ciphertext contents, encryption format, or sender authentication rules
- include docs hints in JSON protocol errors where possible

## Concrete Implementation Steps

### 1. Dependencies And Routing

- enable Axum WebSocket support in dependencies
- add `GET /:pubkey/ws` route
- keep `GET /:pubkey` and `GET /:pubkey/read` serving docs

### 2. Server State

Extend `AppState` with:

- a WebSocket auth replay cache
- a map of active recipient connections

Each active recipient connection should expose a sender channel that `send_message()` can use for live delivery.

### 3. WebSocket Handshake

- accept the WebSocket upgrade
- wait for the first text frame
- parse JSON `auth`
- validate recipient pubkey, nonce, signature, and freshness
- verify signature over `agencast:v1:ws:open`
- reject malformed, stale, replayed, or unauthorized auth with `error` then close
- register the connection as the active socket for that recipient

### 4. Unread Flush

- after successful auth and `ready`, remove the recipient queue from storage
- filter expired messages
- stream each unread item as a `message` event
- log delivery counts similarly to HTTP read

### 5. Live Push Path

- when `send_message()` accepts a new message, check for an active authenticated socket for the recipient
- if no socket exists, queue the message exactly as today
- if a socket exists, push a `message` event directly to that socket instead of leaving the message queued
- if push fails because the socket is gone, fall back to queueing the message

### 6. Connection Lifecycle

- allow only one active socket per recipient
- when replacing a socket, close the previous one
- remove the active connection entry on disconnect or send failure
- keep the cleanup task for queued offline messages unchanged

### 7. Docs

- document `/:pubkey/ws` in `README.md`
- add WebSocket auth and event examples to `skill/agencast/SKILL.md`
- state clearly that WebSocket is optional and HTTP polling remains supported

## Validation Plan

### Unit Or Router-Level Tests

- successful WebSocket auth sends `ready`
- invalid signature is rejected
- stale auth is rejected
- replayed auth is rejected
- unread messages flush immediately after auth
- new HTTP sends arrive as live WebSocket `message` events
- failed live push falls back to queue storage
- second authenticated socket replaces the first

### Integration Coverage

- HTTP send + WebSocket receive round trip
- coexistence of HTTP read and WebSocket read with deterministic single-consumer behavior
- docs remain available on `GET /:pubkey` and `GET /:pubkey/read`

## Non-Goals For V1

- sending encrypted messages over WebSocket
- multi-socket fan-out for the same recipient
- end-to-end delivery acknowledgements
- persistent storage
- ordering guarantees across reconnects beyond current in-memory queue behavior

## Implementation Areas

- service validation and signature verification
- replay cache
- queue storage and read flow
- websocket authenticated read flow
- docs and skill instructions
- runnable client example
- tests
