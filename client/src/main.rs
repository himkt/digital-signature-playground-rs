use std::collections::HashMap;

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::Client;
use serde::Deserialize;
use tokio::main;

#[derive(Deserialize, Debug)]
struct SignResponse {
    signature: String,
}

async fn fetch_signature(client: &Client, message: &str) -> Result<SignResponse, Box<dyn std::error::Error>> {
    let mut params = HashMap::new();
    params.insert("message", message);

    let response = client.post("http://localhost:3000/sign")
        .json(&params)
        .send()
        .await?
        .json::<SignResponse>()
        .await?;

    Ok(response)
}

fn decode_signature(signature: &str) -> Result<Signature, Box<dyn std::error::Error>> {
    let decoded = general_purpose::STANDARD.decode(signature)?;
    let signature = Signature::from_slice(&decoded)?;
    Ok(signature)
}

#[main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifying_key = VerifyingKey::read_public_key_pem_file("./public.pem")?;
    let message = "sample";

    let client = Client::new();
    let response = fetch_signature(&client, message).await?;
    let signature = decode_signature(&response.signature)?;

    verifying_key.verify(message.as_bytes(), &signature)?;
    Ok(())
}
