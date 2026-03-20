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
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, signal, sync::RwLock, time::interval};

const PUBKEY_LEN: usize = 64;
const MESSAGE_TTL: Duration = Duration::from_secs(10 * 60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

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
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
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

    let message_id = state.next_message_id.fetch_add(1, Ordering::Relaxed);
    let message = StoredMessage {
        id: message_id,
        from: payload.from,
        body: payload.body,
        received_at: SystemTime::now(),
        expires_at: Instant::now() + MESSAGE_TTL,
    };

    let mut store = state.store.write().await;
    let queue = store.entry(recipient).or_default();
    queue.retain(|message| !is_expired(message));
    queue.push(message);

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

    let unread = messages
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

    Ok(Json(ReadMessagesResponse { messages: unread }))
}

fn spawn_cleanup_task(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = interval(CLEANUP_INTERVAL);

        loop {
            ticker.tick().await;

            let mut store = state.store.write().await;
            store.retain(|_, messages| {
                messages.retain(|message| !is_expired(message));
                !messages.is_empty()
            });
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
