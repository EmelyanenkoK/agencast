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
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, signal, sync::RwLock, time::interval};

const PUBKEY_LEN: usize = 64;
const MESSAGE_TTL: Duration = Duration::from_secs(10 * 60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const SKILL_TEXT: &str = include_str!("../skill/unibridge/SKILL.md");

#[derive(Clone)]
struct AppState {
    store: Arc<RwLock<HashMap<String, Vec<StoredMessage>>>>,
    next_message_id: Arc<AtomicU64>,
}

#[derive(Debug, Deserialize)]
struct SendMessageRequest {
    from: String,
    body: String,
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
    body: String,
    received_at_unix: u64,
}

#[derive(Debug, Serialize)]
struct ReadMessagesResponse {
    messages: Vec<MessageView>,
}

#[derive(Debug)]
struct StoredMessage {
    id: u64,
    from: String,
    body: String,
    received_at: SystemTime,
    expires_at: Instant,
}

#[tokio::main]
async fn main() {
    let state = AppState {
        store: Arc::new(RwLock::new(HashMap::new())),
        next_message_id: Arc::new(AtomicU64::new(1)),
    };

    spawn_cleanup_task(state.clone());

    let app = Router::new()
        .route("/:pubkey", post(send_message))
        .route("/:pubkey/read", post(read_messages))
        .fallback(fallback_handler)
        .with_state(state);

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

async fn send_message(
    Path(recipient): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<SendMessageRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_pubkey(&recipient)?;
    validate_pubkey(&payload.from)?;

    let recipient_for_log = recipient.clone();
    let from = payload.from;
    let body = payload.body;
    let message_id = state.next_message_id.fetch_add(1, Ordering::Relaxed);
    let message = StoredMessage {
        id: message_id,
        from: from.clone(),
        body: body.clone(),
        received_at: SystemTime::now(),
        expires_at: Instant::now() + MESSAGE_TTL,
    };

    let mut store = state.store.write().await;
    let queue = store.entry(recipient).or_default();
    let expired_removed = retain_unexpired_messages(queue);
    queue.push(message);
    let queue_len = queue.len();

    println!(
        "queued message id={message_id} from={from} to={} queue_len={queue_len} expired_removed={expired_removed} body={}",
        recipient_for_log,
        format_message_for_log(&body),
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
) -> Result<Json<ReadMessagesResponse>, ApiError> {
    validate_pubkey(&recipient)?;

    let mut store = state.store.write().await;
    let messages = match store.remove(&recipient) {
        Some(messages) => messages,
        None => Vec::new(),
    };

    let total_messages = messages.len();
    let unread: Vec<_> = messages
        .into_iter()
        .filter(|message| !is_expired(message))
        .map(|message| MessageView {
            id: message.id,
            from: message.from,
            body: message.body,
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

            let mut store = state.store.write().await;
            let mut expired_removed = 0usize;
            store.retain(|_, messages| {
                expired_removed += count_expired_messages(messages);
                retain_unexpired_messages(messages);
                !messages.is_empty()
            });

            if expired_removed > 0 {
                println!("cleanup removed expired_messages={expired_removed}");
            }
        }
    });
}

fn validate_pubkey(pubkey: &str) -> Result<(), ApiError> {
    let is_valid = pubkey.len() == PUBKEY_LEN
        && pubkey
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());

    if is_valid {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "pubkey must be exactly 64 lowercase hexadecimal characters",
        ))
    }
}

fn is_expired(message: &StoredMessage) -> bool {
    Instant::now() >= message.expires_at
}

fn retain_unexpired_messages(messages: &mut Vec<StoredMessage>) -> usize {
    let before = messages.len();
    messages.retain(|message| !is_expired(message));
    before.saturating_sub(messages.len())
}

fn count_expired_messages(messages: &[StoredMessage]) -> usize {
    messages
        .iter()
        .filter(|message| is_expired(message))
        .count()
}

fn format_message_for_log(body: &str) -> String {
    const MAX_BODY_PREVIEW: usize = 200;

    let sanitized = body.replace('\n', "\\n");
    let mut preview = sanitized.chars().take(MAX_BODY_PREVIEW).collect::<String>();

    if sanitized.chars().count() > MAX_BODY_PREVIEW {
        preview.push_str("...");
    }

    format!("{preview:?}")
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
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.message,
        }));

        (self.status, body).into_response()
    }
}
