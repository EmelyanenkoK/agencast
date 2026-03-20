use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

fn main() {
    let sender_identity = SigningKey::from_bytes(&[1u8; 32]);
    let recipient_identity = SigningKey::from_bytes(&[2u8; 32]);

    let sender_ed25519_hex = hex::encode(sender_identity.verifying_key().to_bytes());
    let recipient_ed25519_hex = hex::encode(recipient_identity.verifying_key().to_bytes());

    // Demo-only fixed X25519 secrets so the example is reproducible.
    // Real clients should generate and persist their own secrets securely.
    let sender_x25519_secret = StaticSecret::from([3u8; 32]);
    let recipient_x25519_secret = StaticSecret::from([4u8; 32]);
    let sender_x25519_public = X25519PublicKey::from(&sender_x25519_secret);
    let recipient_x25519_public = X25519PublicKey::from(&recipient_x25519_secret);

    let sender_x25519_hex = hex::encode(sender_x25519_public.as_bytes());
    let timestamp_ms = 1_770_000_000_000u64;
    let nonce_bytes = [5u8; 24];
    let nonce_hex = hex::encode(nonce_bytes);

    let plaintext = json!({
        "type": "chat",
        "body": "hello over encrypted unibridge",
        "sent_at_ms": timestamp_ms
    })
    .to_string();

    let ciphertext_hex = encrypt_message(
        &sender_x25519_secret,
        &recipient_x25519_public,
        &nonce_bytes,
        plaintext.as_bytes(),
    );

    let send_canonical = canonical_send_message(
        &recipient_ed25519_hex,
        &sender_ed25519_hex,
        &sender_x25519_hex,
        &nonce_hex,
        timestamp_ms,
        &ciphertext_hex,
    );
    let send_signature_hex =
        hex::encode(sender_identity.sign(send_canonical.as_bytes()).to_bytes());

    let send_request = json!({
        "from": sender_ed25519_hex,
        "sender_x25519": sender_x25519_hex,
        "nonce": nonce_hex,
        "timestamp_ms": timestamp_ms,
        "ciphertext": ciphertext_hex,
        "signature": send_signature_hex,
    });

    println!("Send JSON:");
    println!("{}", serde_json::to_string_pretty(&send_request).unwrap());
    println!();
    println!("Canonical string signed for send:");
    println!("{send_canonical}");
    println!();

    let delivered_ciphertext = send_request["ciphertext"].as_str().unwrap();
    let delivered_sender_x25519 = send_request["sender_x25519"].as_str().unwrap();
    let delivered_nonce = send_request["nonce"].as_str().unwrap();

    let delivered_sender_x25519_bytes: [u8; 32] = hex::decode(delivered_sender_x25519)
        .unwrap()
        .try_into()
        .unwrap();
    let delivered_sender_x25519 = X25519PublicKey::from(delivered_sender_x25519_bytes);
    let delivered_nonce_bytes: [u8; 24] = hex::decode(delivered_nonce).unwrap().try_into().unwrap();

    let decrypted = decrypt_message(
        &recipient_x25519_secret,
        &delivered_sender_x25519,
        &delivered_nonce_bytes,
        delivered_ciphertext,
    );

    println!("Decrypted plaintext:");
    println!("{decrypted}");
    println!();

    let read_canonical = canonical_read_message(&recipient_ed25519_hex, timestamp_ms, &nonce_hex);
    let read_signature_hex = hex::encode(
        recipient_identity
            .sign(read_canonical.as_bytes())
            .to_bytes(),
    );
    let read_request = json!({
        "timestamp_ms": timestamp_ms,
        "nonce": nonce_hex,
        "signature": read_signature_hex,
    });

    println!("Read JSON:");
    println!("{}", serde_json::to_string_pretty(&read_request).unwrap());
    println!();
    println!("Canonical string signed for read:");
    println!("{read_canonical}");
}

fn encrypt_message(
    sender_secret: &StaticSecret,
    recipient_public: &X25519PublicKey,
    nonce_bytes: &[u8; 24],
    plaintext: &[u8],
) -> String {
    let key = derive_aead_key(sender_secret, recipient_public);
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XNonce::from_slice(nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).unwrap();
    hex::encode(ciphertext)
}

fn decrypt_message(
    recipient_secret: &StaticSecret,
    sender_public: &X25519PublicKey,
    nonce_bytes: &[u8; 24],
    ciphertext_hex: &str,
) -> String {
    let key = derive_aead_key(recipient_secret, sender_public);
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XNonce::from_slice(nonce_bytes);
    let ciphertext = hex::decode(ciphertext_hex).unwrap();
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    String::from_utf8(plaintext).unwrap()
}

fn derive_aead_key(secret: &StaticSecret, peer_public: &X25519PublicKey) -> Key {
    let shared_secret = secret.diffie_hellman(peer_public);
    let digest = Sha256::digest(shared_secret.as_bytes());
    *Key::from_slice(&digest)
}

fn canonical_send_message(
    recipient: &str,
    from: &str,
    sender_x25519: &str,
    nonce: &str,
    timestamp_ms: u64,
    ciphertext: &str,
) -> String {
    format!(
        "unibridge:v1:send\nrecipient={recipient}\nfrom={from}\nsender_x25519={sender_x25519}\nnonce={nonce}\ntimestamp_ms={timestamp_ms}\nciphertext={ciphertext}"
    )
}

fn canonical_read_message(recipient: &str, timestamp_ms: u64, nonce: &str) -> String {
    format!("unibridge:v1:read\nrecipient={recipient}\ntimestamp_ms={timestamp_ms}\nnonce={nonce}")
}
