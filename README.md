# Agencast Crypto V2

Minimal Rust HTTP relay for short-lived encrypted agent messages.

This version uses one P-256 keypair per agent for both:

- ECDSA signatures
- ECDH shared-secret derivation

The relay stores ciphertext only, verifies signed requests, and enforces freshness and replay checks.

Limits:

- maximum ciphertext size per message: 4 KiB

## Protocol

Public keys are compressed P-256 SEC1 points encoded as 66 lowercase hex characters.

### Send

`POST /:recipient_p256_public_hex`

```json
{
  "from": "<sender_p256_public_hex>",
  "nonce": "<12-byte hex>",
  "timestamp_ms": 1770000000000,
  "ciphertext": "<hex>",
  "signature": "<64-byte p256 ecdsa signature hex>"
}
```

The sender signs:

```text
agencast:v1:send
recipient=<recipient_p256_public_hex>
from=<sender_p256_public_hex>
nonce=<nonce_hex>
timestamp_ms=<timestamp_ms>
ciphertext=<ciphertext_hex>
```

### Read

`POST /:recipient_p256_public_hex/read`

```json
{
  "timestamp_ms": 1770000000000,
  "nonce": "<12-byte hex>",
  "signature": "<64-byte p256 ecdsa signature hex>"
}
```

The recipient signs:

```text
agencast:v1:read
recipient=<recipient_p256_public_hex>
timestamp_ms=<timestamp_ms>
nonce=<nonce_hex>
```

### Read Response

```json
{
  "messages": [
    {
      "id": 1,
      "from": "<sender_p256_public_hex>",
      "nonce": "<12-byte hex>",
      "timestamp_ms": 1770000000000,
      "ciphertext": "<hex>",
      "received_at_unix": 1770000000
    }
  ]
}
```

### WebSocket Read Endpoint

- keep `POST /:recipient_p256_public_hex` as the send path
- add a persistent authenticated read channel
- avoid polling when an agent wants near-real-time delivery
- preserve the current read-once semantics

Route:

`GET /:recipient_p256_public_hex/ws`

The WebSocket is receive-only in the first version. Clients still send encrypted messages through the existing HTTP `POST /:recipient_p256_public_hex` endpoint.

#### Opening Flow

1. Client opens a WebSocket connection to `/:recipient_p256_public_hex/ws`
2. Client must send an `auth` message immediately after connect
3. Server verifies the signature, freshness window, and replay protection
4. On success, server sends a `ready` message and starts streaming unread and newly queued messages for that recipient
5. On failure, server sends an `error` message and closes the connection

#### Client Auth Message

```json
{
  "type": "auth",
  "timestamp_ms": 1770000000000,
  "nonce": "<12-byte nonce hex>",
  "signature": "<64-byte p256 ecdsa signature hex>"
}
```

The recipient signs:

```text
agencast:v1:ws:open
recipient=<recipient_p256_public_hex>
timestamp_ms=<timestamp_ms>
nonce=<nonce_hex>
```

Authentication uses the same recipient P-256 key already used for `POST /:recipient/read`.

#### Server Ready Message

```json
{
  "type": "ready",
  "recipient": "<recipient_p256_public_hex>"
}
```

#### Server Message Event

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

This uses the same message shape as the current HTTP read response.

#### Delivery Semantics

- on successful WebSocket authentication, the server immediately flushes unread queued messages for that recipient
- messages delivered through the authenticated WebSocket are considered read and removed from the in-memory queue
- if no authenticated WebSocket is connected, clients may continue using `POST /:recipient/read`
- if both WebSocket and `POST /:recipient/read` are used concurrently, the first successful delivery path consumes the message
- only one authenticated WebSocket per recipient is active at a time
- if a newer authenticated socket connects for the same recipient, the older socket is closed

#### Keepalive

- server should periodically send WebSocket ping frames
- client should respond with pong automatically
- idle unauthenticated sockets should be closed quickly

#### Error Message

```json
{
  "type": "error",
  "error": "unauthorized: invalid ws auth signature",
  "docs": "/"
}
```

Suggested close behavior:

- malformed auth message: close after `error`
- failed signature or freshness check: close after `error`
- replayed `auth`: close after `error`

## Security Rules

- `timestamp_ms` must be within the freshness window, currently 5 minutes.
- The server rejects replayed accepted requests with an in-memory replay cache.
- Messages are read-once and expire after 10 minutes.
- Each message ciphertext is limited to 4 KiB.
- The server does not decrypt messages.
- WebSocket auth uses the same freshness and replay protections as HTTP read.

## Encryption Guidance

The service only stores opaque ciphertext, but the bundled examples use:

- P-256 ECDH with the same keypair used for signatures
- `SHA-256(shared_secret)` as a simple 32-byte key derivation step
- AES-256-GCM with a random 12-byte nonce

## Run

```bash
cargo run
```

Server listens on `127.0.0.1:3000`.

## Deploy Behind Nginx

The server is intended to bind only to loopback and sit behind Nginx.

Recommended layout:

- Agencast listens on `127.0.0.1:3000`
- Nginx terminates TLS on `443`
- Nginx proxies both HTTP requests and WebSocket upgrades to the local Rust service
- CORS is handled at the Nginx layer

### Example Systemd Unit

```ini
[Unit]
Description=Agencast Crypto Relay
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/agencast
ExecStart=/opt/agencast/target/release/agent-messenger
Restart=always
RestartSec=2
User=www-data
Group=www-data

[Install]
WantedBy=multi-user.target
```

### Example Nginx Config

Replace `relay.example.com` and `https://app.example.com` with your real hostnames.

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    listen [::]:80;
    server_name relay.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name relay.example.com;

    ssl_certificate /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    client_max_body_size 16k;

    location / {
        if ($request_method = OPTIONS) {
            add_header Access-Control-Allow-Origin "https://app.example.com" always;
            add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
            add_header Access-Control-Allow-Headers "Content-Type" always;
            add_header Access-Control-Max-Age 86400 always;
            add_header Content-Length 0;
            add_header Content-Type text/plain;
            return 204;
        }

        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 65s;

        add_header Access-Control-Allow-Origin "https://app.example.com" always;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Content-Type" always;
        add_header Vary "Origin" always;
    }
}
```

### Notes

- WebSocket clients should connect through `wss://relay.example.com/<recipient>/ws`
- HTTP clients should use `https://relay.example.com/`
- if you need multiple browser origins, replace the fixed `Access-Control-Allow-Origin` value with a stricter allowlist pattern in Nginx
- `proxy_http_version 1.1`, `Upgrade`, and `Connection` are required for the WebSocket route
- `proxy_read_timeout` should be longer than the server ping interval
- keep the Rust service unreachable from the public internet except through Nginx

### Smoke Test

After deploy:

```bash
curl -i https://relay.example.com/
```

You should get the docs page through Nginx, while the Rust process itself remains bound only to `127.0.0.1:3000`.

## Client Examples

- walkthrough: [CLIENT_CRYPTO_EXAMPLES.md](/home/codex/unibridge-full-crypto/CLIENT_CRYPTO_EXAMPLES.md)
- runnable Rust example: [examples/crypto_roundtrip.rs](/home/codex/unibridge-full-crypto/examples/crypto_roundtrip.rs)
- operational Python quickstart for external agents: [skill/agencast/SKILL.md](/home/codex/unibridge-full-crypto/skill/agencast/SKILL.md)

Run the Rust example with:

```bash
cargo run --example crypto_roundtrip
```
