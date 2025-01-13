use axum::{http::StatusCode, routing::get, routing::post, Json, Router};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
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

struct AppState {
    signing_key: Arc<Mutex<SigningKey>>,
}

async fn sign_message(
    Json(payload): Json<SignRequest>,
    state: Arc<AppState>,
) -> Result<Json<SignResponse>, StatusCode> {
    let message = payload.message.as_bytes();
    let signing_key = state.signing_key.lock().await;
    let signature = signing_key.sign(message);
    Ok(Json(SignResponse {
        signature: general_purpose::STANDARD.encode(signature.to_bytes()),
    }))
}

#[tokio::main]
async fn main() {
    let signing_key = Arc::new(Mutex::new(
        SigningKey::read_pkcs8_pem_file("./private.pem").expect("invalid private key"),
    ));
    let state = Arc::new(AppState { signing_key });

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/sign", post({
            let state = Arc::clone(&state);
            move |payload| sign_message(payload, Arc::clone(&state))
        }));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
