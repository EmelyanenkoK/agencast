use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::rejection::JsonRejection,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint, PublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, signal, sync::RwLock, time::interval};

const P256_PUBLIC_KEY_HEX_LEN: usize = 66;
const NONCE_HEX_LEN: usize = 24;
const SIGNATURE_HEX_LEN: usize = 128;
const MAX_MESSAGE_BYTES: usize = 4 * 1024;
const MESSAGE_TTL: Duration = Duration::from_secs(10 * 60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const FRESHNESS_WINDOW: Duration = Duration::from_secs(5 * 60);
const SKILL_TEXT: &str = include_str!("../skill/agencast/SKILL.md");
const DOCS_PATH: &str = "/";

#[derive(Clone)]
struct AppState {
    store: Arc<RwLock<HashMap<String, Vec<StoredMessage>>>>,
    send_replay_cache: Arc<RwLock<HashMap<String, Instant>>>,
    read_replay_cache: Arc<RwLock<HashMap<String, Instant>>>,
    next_message_id: Arc<AtomicU64>,
}

impl AppState {
    fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            send_replay_cache: Arc::new(RwLock::new(HashMap::new())),
            read_replay_cache: Arc::new(RwLock::new(HashMap::new())),
            next_message_id: Arc::new(AtomicU64::new(1)),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SendMessageRequest {
    from: String,
    nonce: String,
    timestamp_ms: u64,
    ciphertext: String,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ReadMessagesRequest {
    timestamp_ms: u64,
    nonce: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct SendMessageResponse {
    status: &'static str,
    message_id: u64,
}

#[derive(Debug, Serialize, Clone)]
struct MessageView {
    id: u64,
    from: String,
    nonce: String,
    timestamp_ms: u64,
    ciphertext: String,
    received_at_unix: u64,
}

#[derive(Debug, Serialize)]
struct ReadMessagesResponse {
    messages: Vec<MessageView>,
}

#[derive(Debug, Clone)]
struct StoredMessage {
    id: u64,
    from: String,
    nonce: String,
    timestamp_ms: u64,
    ciphertext: String,
    received_at: SystemTime,
    expires_at: Instant,
}

#[tokio::main]
async fn main() {
    let state = AppState::new();
    spawn_cleanup_task(state.clone());

    let app = build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    println!("listening on http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/:pubkey", get(help_handler).post(send_message))
        .route("/:pubkey/read", get(help_handler).post(read_messages))
        .fallback(fallback_handler)
        .with_state(state)
}

async fn send_message(
    Path(recipient): Path<String>,
    State(state): State<AppState>,
    payload: Result<Json<SendMessageRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(payload) = payload.map_err(api_error_from_json_rejection)?;
    validate_p256_public_key_hex(&recipient, "recipient")?;
    validate_p256_public_key_hex(&payload.from, "from")?;
    validate_nonce_hex(&payload.nonce)?;
    validate_ciphertext_hex(&payload.ciphertext)?;
    validate_signature_hex(&payload.signature)?;
    validate_fresh_timestamp(payload.timestamp_ms)?;

    let canonical = canonical_send_message(
        &recipient,
        &payload.from,
        &payload.nonce,
        payload.timestamp_ms,
        &payload.ciphertext,
    );
    verify_p256_signature(&payload.from, canonical.as_bytes(), &payload.signature)?;

    let replay_key = replay_cache_key("send", &canonical, &payload.signature);
    register_replay_key(
        &state.send_replay_cache,
        replay_key,
        Instant::now() + FRESHNESS_WINDOW,
    )
    .await?;

    let recipient_for_log = recipient.clone();
    let message_id = state.next_message_id.fetch_add(1, Ordering::Relaxed);
    let message = StoredMessage {
        id: message_id,
        from: payload.from.clone(),
        nonce: payload.nonce.clone(),
        timestamp_ms: payload.timestamp_ms,
        ciphertext: payload.ciphertext.clone(),
        received_at: SystemTime::now(),
        expires_at: Instant::now() + MESSAGE_TTL,
    };

    let mut store = state.store.write().await;
    let queue = store.entry(recipient).or_default();
    let expired_removed = retain_unexpired_messages(queue);
    queue.push(message);
    let queue_len = queue.len();

    println!(
        "queued encrypted message id={message_id} from={} to={} queue_len={queue_len} expired_removed={expired_removed} ciphertext={}",
        payload.from,
        recipient_for_log,
        format_hex_preview(&payload.ciphertext),
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(SendMessageResponse {
            status: "queued",
            message_id,
        }),
    ))
}

async fn read_messages(
    Path(recipient): Path<String>,
    State(state): State<AppState>,
    payload: Result<Json<ReadMessagesRequest>, JsonRejection>,
) -> Result<Json<ReadMessagesResponse>, ApiError> {
    let Json(payload) = payload.map_err(api_error_from_json_rejection)?;
    validate_p256_public_key_hex(&recipient, "recipient")?;
    validate_nonce_hex(&payload.nonce)?;
    validate_signature_hex(&payload.signature)?;
    validate_fresh_timestamp(payload.timestamp_ms)?;

    let canonical = canonical_read_message(&recipient, payload.timestamp_ms, &payload.nonce);
    verify_p256_signature(&recipient, canonical.as_bytes(), &payload.signature)?;

    let replay_key = replay_cache_key("read", &canonical, &payload.signature);
    register_replay_key(
        &state.read_replay_cache,
        replay_key,
        Instant::now() + FRESHNESS_WINDOW,
    )
    .await?;

    let mut store = state.store.write().await;
    let messages = store.remove(&recipient).unwrap_or_default();

    let total_messages = messages.len();
    let unread: Vec<_> = messages
        .into_iter()
        .filter(|message| !is_expired(message))
        .map(|message| MessageView {
            id: message.id,
            from: message.from,
            nonce: message.nonce,
            timestamp_ms: message.timestamp_ms,
            ciphertext: message.ciphertext,
            received_at_unix: message
                .received_at
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
        .collect();
    let delivered = unread.len();
    let expired_dropped = total_messages.saturating_sub(delivered);

    println!("read recipient={recipient} delivered={delivered} expired_dropped={expired_dropped}");

    Ok(Json(ReadMessagesResponse { messages: unread }))
}

async fn fallback_handler() -> impl IntoResponse {
    help_response()
}

async fn help_handler() -> impl IntoResponse {
    help_response()
}

fn help_response() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        public_help_text(),
    )
}

fn spawn_cleanup_task(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = interval(CLEANUP_INTERVAL);

        loop {
            ticker.tick().await;

            let expired_messages = {
                let mut store = state.store.write().await;
                let mut expired_removed = 0usize;
                store.retain(|_, messages| {
                    expired_removed += retain_unexpired_messages(messages);
                    !messages.is_empty()
                });
                expired_removed
            };

            let expired_send_replays = {
                let mut cache = state.send_replay_cache.write().await;
                retain_unexpired_replay_entries(&mut cache)
            };

            let expired_read_replays = {
                let mut cache = state.read_replay_cache.write().await;
                retain_unexpired_replay_entries(&mut cache)
            };

            if expired_messages > 0 || expired_send_replays > 0 || expired_read_replays > 0 {
                println!(
                    "cleanup removed expired_messages={expired_messages} expired_send_replays={expired_send_replays} expired_read_replays={expired_read_replays}"
                );
            }
        }
    });
}

fn canonical_send_message(
    recipient: &str,
    from: &str,
    nonce: &str,
    timestamp_ms: u64,
    ciphertext: &str,
) -> String {
    format!(
        "agencast:v1:send\nrecipient={recipient}\nfrom={from}\nnonce={nonce}\ntimestamp_ms={timestamp_ms}\nciphertext={ciphertext}"
    )
}

fn canonical_read_message(recipient: &str, timestamp_ms: u64, nonce: &str) -> String {
    format!("agencast:v1:read\nrecipient={recipient}\ntimestamp_ms={timestamp_ms}\nnonce={nonce}")
}

async fn register_replay_key(
    cache: &Arc<RwLock<HashMap<String, Instant>>>,
    replay_key: String,
    expires_at: Instant,
) -> Result<(), ApiError> {
    let mut cache = cache.write().await;
    retain_expired_replay_entries(&mut cache);

    if cache.contains_key(&replay_key) {
        return Err(ApiError::conflict(
            "duplicate request rejected by replay protection",
        ));
    }

    cache.insert(replay_key, expires_at);
    Ok(())
}

fn validate_p256_public_key_hex(pubkey: &str, field_name: &str) -> Result<(), ApiError> {
    let key_bytes = decode_fixed_hex(pubkey, P256_PUBLIC_KEY_HEX_LEN, field_name)?;
    PublicKey::from_sec1_bytes(&key_bytes).map_err(|_| {
        ApiError::bad_request(format!(
            "{field_name} must be a valid compressed P-256 SEC1 public key"
        ))
    })?;
    Ok(())
}

fn validate_nonce_hex(nonce: &str) -> Result<(), ApiError> {
    decode_fixed_hex(nonce, NONCE_HEX_LEN, "nonce")?;
    Ok(())
}

fn validate_signature_hex(signature: &str) -> Result<(), ApiError> {
    decode_fixed_hex(signature, SIGNATURE_HEX_LEN, "signature")?;
    Ok(())
}

fn validate_ciphertext_hex(ciphertext: &str) -> Result<(), ApiError> {
    if ciphertext.is_empty() {
        return Err(ApiError::bad_request("ciphertext must not be empty"));
    }

    validate_lower_hex(ciphertext, "ciphertext")?;
    if !ciphertext.len().is_multiple_of(2) {
        return Err(ApiError::bad_request(
            "ciphertext must contain an even number of hex characters",
        ));
    }

    let ciphertext_bytes = hex::decode(ciphertext)
        .map_err(|_| ApiError::bad_request("ciphertext must be valid lowercase hexadecimal"))?;

    if ciphertext_bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ApiError::bad_request(format!(
            "ciphertext must not exceed {MAX_MESSAGE_BYTES} bytes"
        )));
    }

    Ok(())
}

fn decode_fixed_hex(
    input: &str,
    expected_hex_len: usize,
    field_name: &str,
) -> Result<Vec<u8>, ApiError> {
    if input.len() != expected_hex_len {
        return Err(ApiError::bad_request(format!(
            "{field_name} must be exactly {expected_hex_len} lowercase hexadecimal characters"
        )));
    }

    validate_lower_hex(input, field_name)?;

    hex::decode(input).map_err(|_| {
        ApiError::bad_request(format!("{field_name} must be valid lowercase hexadecimal"))
    })
}

fn validate_lower_hex(input: &str, field_name: &str) -> Result<(), ApiError> {
    let is_valid = input
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());

    if is_valid {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "{field_name} must be valid lowercase hexadecimal"
        )))
    }
}

fn validate_fresh_timestamp(timestamp_ms: u64) -> Result<(), ApiError> {
    let now_ms = now_unix_ms()?;
    let window_ms = duration_millis_u64(FRESHNESS_WINDOW);

    if now_ms.abs_diff(timestamp_ms) <= window_ms {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "timestamp_ms is outside the allowed freshness window",
        ))
    }
}

fn verify_p256_signature(
    pubkey_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), ApiError> {
    let public_key_bytes = decode_fixed_hex(pubkey_hex, P256_PUBLIC_KEY_HEX_LEN, "public key")?;
    let public_key = PublicKey::from_sec1_bytes(&public_key_bytes).map_err(|_| {
        ApiError::bad_request("public key must be a valid compressed P-256 SEC1 public key")
    })?;

    let verifying_key = VerifyingKey::from_encoded_point(&EncodedPoint::from(public_key))
        .map_err(|_| ApiError::bad_request("public key must be a valid P-256 verifying key"))?;

    let signature_bytes = decode_fixed_hex(signature_hex, SIGNATURE_HEX_LEN, "signature")?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        ApiError::bad_request("signature must decode to a 64-byte fixed-width P-256 signature")
    })?;

    verifying_key
        .verify(message, &signature)
        .map_err(|_| ApiError::unauthorized("signature verification failed"))
}

fn replay_cache_key(scope: &str, canonical: &str, signature_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(scope.as_bytes());
    hasher.update([0]);
    hasher.update(canonical.as_bytes());
    hasher.update([0]);
    hasher.update(signature_hex.as_bytes());
    hex::encode(hasher.finalize())
}

fn retain_unexpired_messages(messages: &mut Vec<StoredMessage>) -> usize {
    let before = messages.len();
    messages.retain(|message| !is_expired(message));
    before.saturating_sub(messages.len())
}

fn retain_unexpired_replay_entries(cache: &mut HashMap<String, Instant>) -> usize {
    let before = cache.len();
    retain_expired_replay_entries(cache);
    before.saturating_sub(cache.len())
}

fn retain_expired_replay_entries(cache: &mut HashMap<String, Instant>) {
    let now = Instant::now();
    cache.retain(|_, expires_at| *expires_at > now);
}

fn is_expired(message: &StoredMessage) -> bool {
    Instant::now() >= message.expires_at
}

fn now_unix_ms() -> Result<u64, ApiError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal("system time is before UNIX epoch"))?
        .as_millis()
        .try_into()
        .map_err(|_| ApiError::internal("system time exceeded supported range"))?)
}

fn duration_millis_u64(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn format_hex_preview(value: &str) -> String {
    const MAX_PREVIEW: usize = 64;

    if value.len() <= MAX_PREVIEW {
        return value.to_owned();
    }

    format!("{}...", &value[..MAX_PREVIEW])
}

fn public_help_text() -> &'static str {
    SKILL_TEXT
        .strip_prefix("---\n")
        .and_then(|rest| {
            rest.split_once("\n---\n")
                .map(|(_, body)| body.trim_start())
        })
        .unwrap_or(SKILL_TEXT)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.message,
            "docs": DOCS_PATH,
            "hint": "See GET / for protocol documentation and request examples.",
        }));

        (self.status, body).into_response()
    }
}

fn api_error_from_json_rejection(rejection: JsonRejection) -> ApiError {
    ApiError::bad_request(format!(
        "invalid JSON request body: {}",
        rejection.body_text()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Method, Request},
    };
    use p256::ecdsa::{signature::Signer, SigningKey};
    use tower::util::ServiceExt;

    const MAX_BODY_BYTES: usize = 1024 * 1024;

    fn signing_key(seed_byte: u8) -> SigningKey {
        let bytes = [seed_byte; 32];
        SigningKey::from_bytes((&bytes).into()).unwrap()
    }

    fn verifying_key_hex(signing_key: &SigningKey) -> String {
        hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
    }

    fn nonce_hex(seed_byte: u8) -> String {
        hex::encode([seed_byte; 12])
    }

    fn ciphertext_hex(seed_byte: u8) -> String {
        hex::encode([seed_byte; 48])
    }

    fn sign_send_request(
        sender: &SigningKey,
        recipient_hex: &str,
        nonce: &str,
        timestamp_ms: u64,
        ciphertext: &str,
    ) -> String {
        let canonical = canonical_send_message(
            recipient_hex,
            &verifying_key_hex(sender),
            nonce,
            timestamp_ms,
            ciphertext,
        );
        let signature: Signature = sender.sign(canonical.as_bytes());
        hex::encode(signature.to_bytes())
    }

    fn sign_read_request(
        recipient: &SigningKey,
        recipient_hex: &str,
        timestamp_ms: u64,
        nonce: &str,
    ) -> String {
        let canonical = canonical_read_message(recipient_hex, timestamp_ms, nonce);
        let signature: Signature = recipient.sign(canonical.as_bytes());
        hex::encode(signature.to_bytes())
    }

    fn tamper_signature_hex(signature_hex: &str) -> String {
        let mut bytes = signature_hex.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).unwrap()
    }

    async fn send_request(router: Router, request: Request<Body>) -> Response {
        router.oneshot(request).await.unwrap()
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn response_text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn valid_signed_send_and_read_are_accepted() {
        let state = AppState::new();
        let router = build_router(state);

        let recipient = signing_key(9);
        let sender = signing_key(7);
        let recipient_hex = verifying_key_hex(&recipient);
        let sender_hex = verifying_key_hex(&sender);
        let nonce = nonce_hex(5);
        let timestamp_ms = now_unix_ms().unwrap();
        let ciphertext = ciphertext_hex(4);
        let signature =
            sign_send_request(&sender, &recipient_hex, &nonce, timestamp_ms, &ciphertext);

        let send_payload = serde_json::json!({
            "from": sender_hex,
            "nonce": nonce,
            "timestamp_ms": timestamp_ms,
            "ciphertext": ciphertext,
            "signature": signature,
        });

        let send_response = send_request(
            router.clone(),
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{recipient_hex}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(send_response.status(), StatusCode::ACCEPTED);

        let read_nonce = nonce_hex(6);
        let read_signature =
            sign_read_request(&recipient, &recipient_hex, timestamp_ms, &read_nonce);
        let read_payload = serde_json::json!({
            "timestamp_ms": timestamp_ms,
            "nonce": read_nonce,
            "signature": read_signature,
        });

        let read_response = send_request(
            router,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{recipient_hex}/read"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(read_payload.to_string()))
                .unwrap(),
        )
        .await;

        assert_eq!(read_response.status(), StatusCode::OK);
        let json = response_json(read_response).await;
        let messages = json["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["from"], sender_hex);
    }

    #[tokio::test]
    async fn invalid_signature_is_rejected() {
        let state = AppState::new();
        let router = build_router(state);

        let recipient = signing_key(11);
        let sender = signing_key(12);
        let recipient_hex = verifying_key_hex(&recipient);
        let sender_hex = verifying_key_hex(&sender);
        let nonce = nonce_hex(14);
        let timestamp_ms = now_unix_ms().unwrap();
        let ciphertext = ciphertext_hex(15);
        let signature = tamper_signature_hex(&sign_send_request(
            &sender,
            &recipient_hex,
            &nonce,
            timestamp_ms,
            &ciphertext,
        ));

        let payload = serde_json::json!({
            "from": sender_hex,
            "nonce": nonce,
            "timestamp_ms": timestamp_ms,
            "ciphertext": ciphertext,
            "signature": signature,
        });

        let response = send_request(
            router,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{recipient_hex}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = response_json(response).await;
        assert_eq!(json["docs"], DOCS_PATH);
    }

    #[tokio::test]
    async fn malformed_hex_is_rejected() {
        let state = AppState::new();
        let router = build_router(state);

        let recipient = signing_key(21);
        let sender = signing_key(22);
        let recipient_hex = verifying_key_hex(&recipient);
        let sender_hex = verifying_key_hex(&sender);
        let timestamp_ms = now_unix_ms().unwrap();
        let payload = serde_json::json!({
            "from": sender_hex,
            "nonce": "xyz",
            "timestamp_ms": timestamp_ms,
            "ciphertext": ciphertext_hex(24),
            "signature": sign_send_request(
                &sender,
                &recipient_hex,
                &nonce_hex(23),
                timestamp_ms,
                &ciphertext_hex(24),
            ),
        });

        let response = send_request(
            router,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{recipient_hex}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["docs"], DOCS_PATH);
    }

    #[tokio::test]
    async fn stale_timestamp_is_rejected() {
        let state = AppState::new();
        let router = build_router(state);

        let recipient = signing_key(31);
        let sender = signing_key(32);
        let recipient_hex = verifying_key_hex(&recipient);
        let sender_hex = verifying_key_hex(&sender);
        let nonce = nonce_hex(34);
        let timestamp_ms = now_unix_ms().unwrap() - duration_millis_u64(FRESHNESS_WINDOW) - 1;
        let ciphertext = ciphertext_hex(35);
        let signature =
            sign_send_request(&sender, &recipient_hex, &nonce, timestamp_ms, &ciphertext);

        let payload = serde_json::json!({
            "from": sender_hex,
            "nonce": nonce,
            "timestamp_ms": timestamp_ms,
            "ciphertext": ciphertext,
            "signature": signature,
        });

        let response = send_request(
            router,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{recipient_hex}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["docs"], DOCS_PATH);
    }

    #[tokio::test]
    async fn oversized_ciphertext_is_rejected() {
        let state = AppState::new();
        let router = build_router(state);

        let recipient = signing_key(36);
        let sender = signing_key(37);
        let recipient_hex = verifying_key_hex(&recipient);
        let sender_hex = verifying_key_hex(&sender);
        let nonce = nonce_hex(38);
        let timestamp_ms = now_unix_ms().unwrap();
        let ciphertext = hex::encode(vec![0x42; MAX_MESSAGE_BYTES + 1]);
        let signature =
            sign_send_request(&sender, &recipient_hex, &nonce, timestamp_ms, &ciphertext);

        let payload = serde_json::json!({
            "from": sender_hex,
            "nonce": nonce,
            "timestamp_ms": timestamp_ms,
            "ciphertext": ciphertext,
            "signature": signature,
        });

        let response = send_request(
            router,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{recipient_hex}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["docs"], DOCS_PATH);
    }

    #[tokio::test]
    async fn duplicate_send_is_rejected() {
        let state = AppState::new();
        let router = build_router(state);

        let recipient = signing_key(41);
        let sender = signing_key(42);
        let recipient_hex = verifying_key_hex(&recipient);
        let sender_hex = verifying_key_hex(&sender);
        let nonce = nonce_hex(44);
        let timestamp_ms = now_unix_ms().unwrap();
        let ciphertext = ciphertext_hex(45);
        let signature =
            sign_send_request(&sender, &recipient_hex, &nonce, timestamp_ms, &ciphertext);

        let payload = serde_json::json!({
            "from": sender_hex,
            "nonce": nonce,
            "timestamp_ms": timestamp_ms,
            "ciphertext": ciphertext,
            "signature": signature,
        })
        .to_string();

        let first = send_request(
            router.clone(),
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{recipient_hex}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::ACCEPTED);

        let second = send_request(
            router,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{recipient_hex}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;
        assert_eq!(second.status(), StatusCode::CONFLICT);
        let json = response_json(second).await;
        assert_eq!(json["docs"], DOCS_PATH);
    }

    #[tokio::test]
    async fn duplicate_read_is_rejected() {
        let state = AppState::new();
        let router = build_router(state);

        let recipient = signing_key(51);
        let recipient_hex = verifying_key_hex(&recipient);
        let timestamp_ms = now_unix_ms().unwrap();
        let nonce = nonce_hex(52);
        let signature = sign_read_request(&recipient, &recipient_hex, timestamp_ms, &nonce);

        let payload = serde_json::json!({
            "timestamp_ms": timestamp_ms,
            "nonce": nonce,
            "signature": signature,
        })
        .to_string();

        let first = send_request(
            router.clone(),
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{recipient_hex}/read"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);

        let second = send_request(
            router,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{recipient_hex}/read"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;
        assert_eq!(second.status(), StatusCode::CONFLICT);
        let json = response_json(second).await;
        assert_eq!(json["docs"], DOCS_PATH);
    }

    #[tokio::test]
    async fn expired_messages_are_dropped_on_read() {
        let state = AppState::new();
        let recipient = signing_key(61);
        let recipient_hex = verifying_key_hex(&recipient);

        {
            let mut store = state.store.write().await;
            store.insert(
                recipient_hex.clone(),
                vec![StoredMessage {
                    id: 1,
                    from: verifying_key_hex(&signing_key(62)),
                    nonce: nonce_hex(64),
                    timestamp_ms: now_unix_ms().unwrap(),
                    ciphertext: ciphertext_hex(65),
                    received_at: SystemTime::now(),
                    expires_at: Instant::now() - Duration::from_secs(1),
                }],
            );
        }

        let router = build_router(state);
        let read_nonce = nonce_hex(66);
        let timestamp_ms = now_unix_ms().unwrap();
        let signature = sign_read_request(&recipient, &recipient_hex, timestamp_ms, &read_nonce);
        let payload = serde_json::json!({
            "timestamp_ms": timestamp_ms,
            "nonce": read_nonce,
            "signature": signature,
        });

        let response = send_request(
            router,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{recipient_hex}/read"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["messages"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn get_keyed_paths_render_help_text() {
        let state = AppState::new();
        let router = build_router(state);
        let pubkey = verifying_key_hex(&signing_key(71));

        let response = send_request(
            router.clone(),
            Request::builder()
                .method(Method::GET)
                .uri(format!("/{pubkey}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_text(response).await;
        assert!(body.contains("## Security"));

        let read_response = send_request(
            router,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/{pubkey}/read"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(read_response.status(), StatusCode::OK);
        let read_body = response_text(read_response).await;
        assert!(read_body.contains("## Exact Payload Shape"));
    }

    #[tokio::test]
    async fn malformed_json_includes_docs_pointer() {
        let state = AppState::new();
        let router = build_router(state);
        let recipient_hex = verifying_key_hex(&signing_key(72));

        let response = send_request(
            router,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{recipient_hex}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["docs"], DOCS_PATH);
        assert_eq!(
            json["hint"],
            "See GET / for protocol documentation and request examples."
        );
    }
}
