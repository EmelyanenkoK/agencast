use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};

static TEST_LOCK: Mutex<()> = Mutex::new(());

struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn valid_signed_send_and_read_round_trip() {
    let _guard = test_lock();
    let server = spawn_server();

    let recipient = signing_key_from_seed(2);
    let sender = signing_key_from_seed(1);
    let recipient_hex = pubkey_hex(&recipient);
    let sender_hex = pubkey_hex(&sender);
    let nonce = repeat_hex("11", 12);
    let timestamp_ms = current_timestamp_ms();
    let ciphertext = "00112233445566778899aabbccddeeff";

    let send_body = send_request_json(
        &recipient_hex,
        &sender,
        &sender_hex,
        &nonce,
        timestamp_ms,
        ciphertext,
    );
    let send_response = post_json(&format!("/{recipient_hex}"), &send_body);
    assert_eq!(
        send_response.status, 202,
        "send response: {}",
        send_response.body
    );

    let send_json: Value = serde_json::from_str(&send_response.body).unwrap();
    assert_eq!(send_json["status"], "queued");
    let message_id = send_json["message_id"]
        .as_u64()
        .expect("send response message_id");

    let read_body = read_request_json(&recipient_hex, &recipient, &nonce, timestamp_ms);
    let read_response = post_json(&format!("/{recipient_hex}/read"), &read_body);
    assert_eq!(
        read_response.status, 200,
        "read response: {}",
        read_response.body
    );

    let read_json: Value = serde_json::from_str(&read_response.body).unwrap();
    let messages = read_json["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 1);

    let message = &messages[0];
    assert_eq!(message["id"].as_u64(), Some(message_id));
    assert_eq!(message["from"], sender_hex);
    assert_eq!(message["nonce"], nonce);
    assert_eq!(message["timestamp_ms"], timestamp_ms);
    assert_eq!(message["ciphertext"], ciphertext);
    assert!(message["received_at_unix"].as_u64().is_some());

    drop(server);
}

#[test]
fn invalid_signature_is_rejected() {
    let _guard = test_lock();
    let server = spawn_server();

    let recipient = signing_key_from_seed(4);
    let sender = signing_key_from_seed(3);
    let recipient_hex = pubkey_hex(&recipient);
    let sender_hex = pubkey_hex(&sender);
    let nonce = repeat_hex("44", 12);
    let timestamp_ms = current_timestamp_ms();
    let ciphertext = "aabbccdd";

    let mut body = send_request_json(
        &recipient_hex,
        &sender,
        &sender_hex,
        &nonce,
        timestamp_ms,
        ciphertext,
    );
    let mut payload: Value = serde_json::from_str(&body).unwrap();
    payload["signature"] = Value::String(tamper_signature(payload["signature"].as_str().unwrap()));
    body = serde_json::to_string(&payload).unwrap();

    let response = post_json(&format!("/{recipient_hex}"), &body);
    assert_eq!(response.status, 401, "response: {}", response.body);

    drop(server);
}

#[test]
fn malformed_hex_is_rejected() {
    let _guard = test_lock();
    let server = spawn_server();

    let recipient = signing_key_from_seed(6);
    let sender = signing_key_from_seed(5);
    let recipient_hex = pubkey_hex(&recipient);
    let sender_hex = pubkey_hex(&sender);
    let nonce = "this-is-not-hex";
    let timestamp_ms = current_timestamp_ms();
    let ciphertext = "ffee";

    let body = send_request_json(
        &recipient_hex,
        &sender,
        &sender_hex,
        nonce,
        timestamp_ms,
        ciphertext,
    );

    let response = post_json(&format!("/{recipient_hex}"), &body);
    assert_eq!(response.status, 400, "response: {}", response.body);

    drop(server);
}

#[test]
fn stale_timestamp_is_rejected() {
    let _guard = test_lock();
    let server = spawn_server();

    let recipient = signing_key_from_seed(8);
    let sender = signing_key_from_seed(7);
    let recipient_hex = pubkey_hex(&recipient);
    let sender_hex = pubkey_hex(&sender);
    let nonce = repeat_hex("77", 12);
    let timestamp_ms = 1u64;
    let ciphertext = "deadbeef";

    let body = send_request_json(
        &recipient_hex,
        &sender,
        &sender_hex,
        &nonce,
        timestamp_ms,
        ciphertext,
    );

    let response = post_json(&format!("/{recipient_hex}"), &body);
    assert_eq!(response.status, 400, "response: {}", response.body);

    drop(server);
}

#[test]
fn duplicate_send_is_rejected() {
    let _guard = test_lock();
    let server = spawn_server();

    let recipient = signing_key_from_seed(10);
    let sender = signing_key_from_seed(9);
    let recipient_hex = pubkey_hex(&recipient);
    let sender_hex = pubkey_hex(&sender);
    let nonce = repeat_hex("99", 12);
    let timestamp_ms = current_timestamp_ms();
    let ciphertext = "cafebabe";

    let body = send_request_json(
        &recipient_hex,
        &sender,
        &sender_hex,
        &nonce,
        timestamp_ms,
        ciphertext,
    );

    let first = post_json(&format!("/{recipient_hex}"), &body);
    assert_eq!(first.status, 202, "first send: {}", first.body);

    let second = post_json(&format!("/{recipient_hex}"), &body);
    assert_eq!(second.status, 409, "duplicate send: {}", second.body);

    drop(server);
}

#[test]
fn oversized_ciphertext_is_rejected() {
    let _guard = test_lock();
    let server = spawn_server();

    let recipient = signing_key_from_seed(14);
    let sender = signing_key_from_seed(13);
    let recipient_hex = pubkey_hex(&recipient);
    let sender_hex = pubkey_hex(&sender);
    let nonce = repeat_hex("cc", 12);
    let timestamp_ms = current_timestamp_ms();
    let ciphertext = "ab".repeat(4097);

    let body = send_request_json(
        &recipient_hex,
        &sender,
        &sender_hex,
        &nonce,
        timestamp_ms,
        &ciphertext,
    );

    let response = post_json(&format!("/{recipient_hex}"), &body);
    assert_eq!(response.status, 400, "response: {}", response.body);

    drop(server);
}

#[test]
fn duplicate_read_is_rejected() {
    let _guard = test_lock();
    let server = spawn_server();

    let recipient = signing_key_from_seed(12);
    let sender = signing_key_from_seed(11);
    let recipient_hex = pubkey_hex(&recipient);
    let sender_hex = pubkey_hex(&sender);
    let nonce = repeat_hex("bb", 12);
    let timestamp_ms = current_timestamp_ms();
    let ciphertext = "abcd";

    let send_body = send_request_json(
        &recipient_hex,
        &sender,
        &sender_hex,
        &nonce,
        timestamp_ms,
        ciphertext,
    );
    let send_response = post_json(&format!("/{recipient_hex}"), &send_body);
    assert_eq!(
        send_response.status, 202,
        "send response: {}",
        send_response.body
    );

    let read_body = read_request_json(&recipient_hex, &recipient, &nonce, timestamp_ms);
    let first = post_json(&format!("/{recipient_hex}/read"), &read_body);
    assert_eq!(first.status, 200, "first read: {}", first.body);
    let first_json: Value = serde_json::from_str(&first.body).unwrap();
    assert_eq!(first_json["messages"].as_array().unwrap().len(), 1);

    let second = post_json(&format!("/{recipient_hex}/read"), &read_body);
    assert_eq!(second.status, 409, "duplicate read: {}", second.body);

    drop(server);
}

#[test]
#[ignore = "requires a deterministic clock or TTL override hook in the server"]
fn expired_messages_are_dropped() {
    let _guard = test_lock();
    let _server = spawn_server();
    let _ = ();
}

fn spawn_server() -> ServerGuard {
    let binary = binary_path();
    let child = Command::new(binary)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn agent-messenger");

    wait_for_server();

    ServerGuard { child }
}

fn wait_for_server() {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect("127.0.0.1:3000") {
            Ok(stream) => {
                let _ = stream.shutdown(Shutdown::Both);
                return;
            }
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Err(err) => panic!("server did not start in time: {err}"),
        }
    }
}

fn post_json(path: &str, body: &str) -> HttpResponse {
    let mut stream = TcpStream::connect("127.0.0.1:3000").expect("failed to connect to server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("failed to set read timeout");

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .expect("failed to write request");
    stream.flush().expect("failed to flush request");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("failed to read response");

    parse_http_response(&response)
}

fn parse_http_response(bytes: &[u8]) -> HttpResponse {
    let raw = String::from_utf8(bytes.to_vec()).expect("response was not valid utf-8");
    let (headers, body) = raw
        .split_once("\r\n\r\n")
        .expect("missing HTTP header/body separator");
    let mut lines = headers.lines();
    let status_line = lines.next().expect("missing HTTP status line");
    let mut parts = status_line.splitn(3, ' ');
    let _http_version = parts.next().expect("missing HTTP version");
    let status = parts
        .next()
        .expect("missing HTTP status code")
        .parse::<u16>()
        .expect("invalid HTTP status code");

    HttpResponse {
        status,
        body: body.to_string(),
    }
}

fn send_request_json(
    recipient_hex: &str,
    sender: &SigningKey,
    sender_hex: &str,
    nonce: &str,
    timestamp_ms: u64,
    ciphertext: &str,
) -> String {
    let canonical = format!(
        "agencast:v1:send\nrecipient={recipient_hex}\nfrom={sender_hex}\nnonce={nonce}\ntimestamp_ms={timestamp_ms}\nciphertext={ciphertext}"
    );
    let signature: Signature = sender.sign(canonical.as_bytes());

    json!({
        "from": sender_hex,
        "nonce": nonce,
        "timestamp_ms": timestamp_ms,
        "ciphertext": ciphertext,
        "signature": hex::encode(signature.to_bytes()),
    })
    .to_string()
}

fn read_request_json(
    recipient_hex: &str,
    recipient: &SigningKey,
    nonce: &str,
    timestamp_ms: u64,
) -> String {
    let canonical = format!(
        "agencast:v1:read\nrecipient={recipient_hex}\ntimestamp_ms={timestamp_ms}\nnonce={nonce}"
    );
    let signature: Signature = recipient.sign(canonical.as_bytes());

    json!({
        "timestamp_ms": timestamp_ms,
        "nonce": nonce,
        "signature": hex::encode(signature.to_bytes()),
    })
    .to_string()
}

fn tamper_signature(signature_hex: &str) -> String {
    let mut bytes = signature_hex.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).expect("signature hex must be utf-8")
}

fn signing_key_from_seed(seed: u8) -> SigningKey {
    let bytes = [seed; 32];
    SigningKey::from_bytes((&bytes).into()).unwrap()
}

fn pubkey_hex(signing_key: &SigningKey) -> String {
    hex::encode(
        signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    )
}

fn repeat_hex(byte_hex: &str, count: usize) -> String {
    byte_hex.repeat(count)
}

fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis()
        .try_into()
        .expect("timestamp overflow")
}

fn binary_path() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_agent-messenger") {
        return PathBuf::from(path);
    }

    if let Ok(path) = std::env::var("CARGO_BIN_EXE_agent_messenger") {
        return PathBuf::from(path);
    }

    if let Some(path) = option_env!("CARGO_BIN_EXE_agent-messenger") {
        return PathBuf::from(path);
    }

    if let Some(path) = option_env!("CARGO_BIN_EXE_agent_messenger") {
        return PathBuf::from(path);
    }

    panic!("cargo did not expose the agent-messenger binary path")
}

struct HttpResponse {
    status: u16,
    body: String,
}

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
