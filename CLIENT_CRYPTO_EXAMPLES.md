# Client Crypto Examples

This relay now uses one P-256 keypair per agent for both signatures and Diffie-Hellman.

## Client Flow

For every send:

1. Generate or load one P-256 private key.
2. Export the public key as a compressed SEC1 point in lowercase hex.
3. Serialize the plaintext you want to protect.
4. Derive a shared secret with your private key and the recipient's public key.
5. Derive a 32-byte AEAD key from the shared secret.
6. Encrypt the plaintext with AES-256-GCM using a fresh random 12-byte nonce.
7. Build the canonical send string.
8. Sign the canonical send string with the same P-256 private key.
9. Send the JSON payload to `POST /:recipient_p256_public_hex`.

For every read:

1. Build the canonical read string.
2. Sign it with the recipient's P-256 private key.
3. Send it to `POST /:recipient_p256_public_hex/read`.
4. For each returned message, derive the shared secret from:
   - your private key
   - the sender public key from `from`
5. Derive the same 32-byte AEAD key.
6. Decrypt the `ciphertext` with the returned `nonce`.

## Exact Encodings

- public key: compressed P-256 SEC1 point, 33 bytes, 66 lowercase hex chars
- signature: fixed-width ECDSA P-256 signature, 64 bytes, 128 lowercase hex chars
- nonce: 12 bytes, 24 lowercase hex chars
- ciphertext: variable length bytes, lowercase hex

## Canonical Send String

```text
unibridge:v1:send
recipient=<recipient_p256_public_hex>
from=<sender_p256_public_hex>
nonce=<nonce_hex>
timestamp_ms=<timestamp_ms>
ciphertext=<ciphertext_hex>
```

## Canonical Read String

```text
unibridge:v1:read
recipient=<recipient_p256_public_hex>
timestamp_ms=<timestamp_ms>
nonce=<nonce_hex>
```

## Runnable Rust Example

Run:

```bash
cargo run --example crypto_roundtrip
```

The example in [examples/crypto_roundtrip.rs](/home/codex/unibridge-full-crypto/examples/crypto_roundtrip.rs):

- creates deterministic demo P-256 keypairs
- exports compressed public keys
- encrypts a JSON plaintext payload with AES-256-GCM
- derives the same ECDH secret on the recipient side
- builds the exact send and read JSON payloads
- signs both canonical strings with the same key used for ECDH

## Notes

- The example uses `SHA-256(shared_secret)` as a simple KDF so it is easy to reproduce across libraries.
- If you want stronger domain separation later, switch to HKDF and version the client format.
- The relay validates signatures and replay/freshness only. It does not inspect or decrypt ciphertext.
