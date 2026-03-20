use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use p256::{
    ecdh::diffie_hellman,
    ecdsa::{signature::Signer, Signature, SigningKey},
    PublicKey, SecretKey,
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn main() {
    let sender_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let recipient_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();

    let sender_signing_key = SigningKey::from(sender_secret.clone());
    let recipient_signing_key = SigningKey::from(recipient_secret.clone());

    let sender_public_hex = public_key_hex(&sender_signing_key);
    let recipient_public_hex = public_key_hex(&recipient_signing_key);

    let sender_public =
        PublicKey::from_sec1_bytes(&hex::decode(&sender_public_hex).unwrap()).unwrap();
    let recipient_public =
        PublicKey::from_sec1_bytes(&hex::decode(&recipient_public_hex).unwrap()).unwrap();

    let timestamp_ms = 1_770_000_000_000u64;
    let nonce_bytes = [5u8; 12];
    let nonce_hex = hex::encode(nonce_bytes);

    let plaintext = json!({
        "type": "chat",
        "body": "hello over encrypted unibridge",
        "sent_at_ms": timestamp_ms
    })
    .to_string();

    let ciphertext_hex = encrypt_message(
        &sender_secret,
        &recipient_public,
        &nonce_bytes,
        plaintext.as_bytes(),
    );

    let send_canonical = canonical_send_message(
        &recipient_public_hex,
        &sender_public_hex,
        &nonce_hex,
        timestamp_ms,
        &ciphertext_hex,
    );
    let send_signature: Signature = sender_signing_key.sign(send_canonical.as_bytes());

    let send_request = json!({
        "from": sender_public_hex,
        "nonce": nonce_hex,
        "timestamp_ms": timestamp_ms,
        "ciphertext": ciphertext_hex,
        "signature": hex::encode(send_signature.to_bytes()),
    });

    println!("Send JSON:");
    println!("{}", serde_json::to_string_pretty(&send_request).unwrap());
    println!();
    println!("Canonical string signed for send:");
    println!("{send_canonical}");
    println!();

    let delivered_ciphertext = send_request["ciphertext"].as_str().unwrap();
    let delivered_sender_public =
        PublicKey::from_sec1_bytes(&hex::decode(send_request["from"].as_str().unwrap()).unwrap())
            .unwrap();
    let delivered_nonce: [u8; 12] = hex::decode(send_request["nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let decrypted = decrypt_message(
        &recipient_secret,
        &delivered_sender_public,
        &delivered_nonce,
        delivered_ciphertext,
    );

    println!("Decrypted plaintext:");
    println!("{decrypted}");
    println!();

    let read_canonical = canonical_read_message(&recipient_public_hex, timestamp_ms, &nonce_hex);
    let read_signature: Signature = recipient_signing_key.sign(read_canonical.as_bytes());
    let read_request = json!({
        "timestamp_ms": timestamp_ms,
        "nonce": nonce_hex,
        "signature": hex::encode(read_signature.to_bytes()),
    });

    println!("Read JSON:");
    println!("{}", serde_json::to_string_pretty(&read_request).unwrap());
    println!();
    println!("Canonical string signed for read:");
    println!("{read_canonical}");

    let _ = sender_public;
}

fn encrypt_message(
    sender_secret: &SecretKey,
    recipient_public: &PublicKey,
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
) -> String {
    let key = derive_aead_key(sender_secret, recipient_public);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).unwrap();
    hex::encode(ciphertext)
}

fn decrypt_message(
    recipient_secret: &SecretKey,
    sender_public: &PublicKey,
    nonce_bytes: &[u8; 12],
    ciphertext_hex: &str,
) -> String {
    let key = derive_aead_key(recipient_secret, sender_public);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = hex::decode(ciphertext_hex).unwrap();
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    String::from_utf8(plaintext).unwrap()
}

fn derive_aead_key(secret: &SecretKey, peer_public: &PublicKey) -> Key<Aes256Gcm> {
    let shared_secret = diffie_hellman(secret.to_nonzero_scalar(), peer_public.as_affine());
    let digest = Sha256::digest(shared_secret.raw_secret_bytes());
    *Key::<Aes256Gcm>::from_slice(&digest)
}

fn public_key_hex(signing_key: &SigningKey) -> String {
    hex::encode(
        signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    )
}

fn canonical_send_message(
    recipient: &str,
    from: &str,
    nonce: &str,
    timestamp_ms: u64,
    ciphertext: &str,
) -> String {
    format!(
        "unibridge:v1:send\nrecipient={recipient}\nfrom={from}\nnonce={nonce}\ntimestamp_ms={timestamp_ms}\nciphertext={ciphertext}"
    )
}

fn canonical_read_message(recipient: &str, timestamp_ms: u64, nonce: &str) -> String {
    format!("unibridge:v1:read\nrecipient={recipient}\ntimestamp_ms={timestamp_ms}\nnonce={nonce}")
}
