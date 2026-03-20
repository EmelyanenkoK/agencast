# Unibridge P-256 Execution Plan

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

- `/:pubkey` and `/:pubkey/read`
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
unibridge:v1:send
recipient=<recipient_p256_public_hex>
from=<sender_p256_public_hex>
nonce=<nonce_hex>
timestamp_ms=<timestamp_ms>
ciphertext=<ciphertext_hex>
```

### Canonical Read String

```text
unibridge:v1:read
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

## Implementation Areas

- service validation and signature verification
- replay cache
- queue storage and read flow
- docs and skill instructions
- runnable client example
- tests
