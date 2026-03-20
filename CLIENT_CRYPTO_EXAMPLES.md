# Client Crypto Examples

This file shows the exact client-side flow the relay expects.

## What The Client Must Do

For every send:

1. Serialize the plaintext message you want to protect.
2. Derive a shared secret with X25519.
3. Turn that shared secret into a 32-byte AEAD key.
4. Encrypt the plaintext with XChaCha20-Poly1305.
5. Hex-encode:
   - sender Ed25519 public key
   - sender X25519 public key
   - 24-byte nonce
   - ciphertext
6. Build the canonical send string.
7. Sign that canonical string with the sender's Ed25519 secret key.
8. Send the JSON payload to `POST /:recipient_ed25519`.

For every read:

1. Build the canonical read string.
2. Sign it with the recipient's Ed25519 secret key.
3. Send the JSON payload to `POST /:recipient_ed25519/read`.
4. For each returned message, derive the shared secret from:
   - recipient X25519 secret key
   - `sender_x25519` from the message
5. Decrypt the returned `ciphertext` with the message `nonce`.

## Important Separation

The relay path uses an Ed25519 public key, but encryption uses X25519.

- `/:pubkey` is the recipient Ed25519 identity key.
- `sender_x25519` is included in each encrypted message so the recipient can derive the shared secret for decryption.
- The sender must know the recipient's X25519 public key out of band.

## Exact Encodings

- Ed25519 public key: 32 bytes, encoded as 64 lowercase hex chars
- X25519 public key: 32 bytes, encoded as 64 lowercase hex chars
- XChaCha20-Poly1305 nonce: 24 bytes, encoded as 48 lowercase hex chars
- Ed25519 signature: 64 bytes, encoded as 128 lowercase hex chars
- Ciphertext: variable length bytes, encoded as lowercase hex

## Canonical Send String

```text
unibridge:v1:send
recipient=<recipient_ed25519_hex>
from=<sender_ed25519_hex>
sender_x25519=<sender_x25519_hex>
nonce=<nonce_hex>
timestamp_ms=<timestamp_ms>
ciphertext=<ciphertext_hex>
```

## Canonical Read String

```text
unibridge:v1:read
recipient=<recipient_ed25519_hex>
timestamp_ms=<timestamp_ms>
nonce=<nonce_hex>
```

## Runnable Example

Run:

```bash
cargo run --example crypto_roundtrip
```

The example in [examples/crypto_roundtrip.rs](/home/codex/unibridge-full-crypto/examples/crypto_roundtrip.rs):

- creates deterministic demo Ed25519 and X25519 keys
- encrypts a JSON plaintext payload
- builds the exact send JSON expected by the relay
- signs the canonical send string
- decrypts the ciphertext on the recipient side
- builds the exact signed read JSON

## Minimal Rust Pattern

```rust
let shared_secret = sender_x25519_secret.diffie_hellman(&recipient_x25519_public);
let key = Sha256::digest(shared_secret.as_bytes());
let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
let nonce = XNonce::from_slice(&nonce_bytes);
let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())?;
```

```rust
let canonical = format!(
    "unibridge:v1:send\nrecipient={recipient}\nfrom={from}\nsender_x25519={sender_x25519}\nnonce={nonce}\ntimestamp_ms={timestamp_ms}\nciphertext={ciphertext}"
);
let signature = sender_ed25519_secret.sign(canonical.as_bytes());
```

## Notes

- The example uses `Sha256(shared_secret)` as a simple 32-byte key derivation step so it is easy to reproduce.
- If you want stronger domain separation later, switch this to HKDF and version the client format.
- The server does not decrypt ciphertext and does not verify that `sender_x25519` is linked to `from`. That binding is only established by the signed request.
