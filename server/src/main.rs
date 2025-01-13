use axum::{http::StatusCode, routing::get, routing::post, Json, Router};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Deserialize)]
struct SignRequest {
    message: String,
}

#[derive(Serialize)]
struct SignResponse {
    signature: String,
}

async fn sign_message(Json(payload): Json<SignRequest>) -> Result<Json<SignResponse>, StatusCode> {
    let message = payload.message.as_bytes();
    let signing_key = Arc::new(Mutex::new(
        SigningKey::read_pkcs8_pem_file("./private.pem").expect("invalid private key"),
    ));
    let signature = signing_key.lock().await.sign(message);
    Ok(Json(SignResponse {
        signature: general_purpose::STANDARD.encode(signature.to_bytes()),
    }))
}

#[tokio::main]
async fn main() {
    let signing_key = Arc::new(Mutex::new(
        SigningKey::read_pkcs8_pem_file("./private.pem").expect("invalid private key"),
    ));
    let verifying_key = VerifyingKey::read_public_key_pem_file("./public.pem").expect("invalid public key");

    let message: &[u8] = b"This is a test of the tsunami alert system.";
    let signature: Signature = signing_key.lock().await.sign(message);

    // verify with private key
    assert!(signing_key.lock().await.verify(message, &signature).is_ok());

    // verify with public key
    assert!(verifying_key.verify(message, &signature).is_ok());

    // build our application with a single route
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/sign", post(sign_message));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
