use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use anyhow::{Context, Result};
use hex;
use risc0_zkvm::{Digest, Receipt};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer; // Hinzufügen für das Body-Limit

#[derive(Deserialize)]
struct ReceiptExport {
    image_id: String,
    receipt: Receipt,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    message: String,
    journal_value: Option<u32>,
}

async fn verify_receipt_handler(Json(payload): Json<ReceiptExport>) -> impl IntoResponse {
    match verify_receipt(payload).await {
        Ok(response) => (StatusCode::OK, Json(response)),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(VerifyResponse {
                valid: false,
                message: e.to_string(),
                journal_value: None,
            }),
        ),
    }
}

async fn verify_receipt(export: ReceiptExport) -> Result<VerifyResponse> {
    println!("--- Start Receipt Verification ---");
    println!("Empfangene Image ID (String): {}", export.image_id);

    let image_id_vec = hex::decode(&export.image_id)
        .context("Konvertierung der Image-ID in Bytes fehlgeschlagen")?;
    println!("Image ID als Bytes (Vec<u8>): {:?}", image_id_vec);

    let image_id_bytes: [u8; 32] = image_id_vec.try_into().map_err(|e| {
        println!("Fehler bei try_into für Image ID: {:?}", e);
        anyhow::anyhow!("Die Image-ID hat nicht die erwartete Länge von 32 Bytes")
    })?;
    println!("Image ID als Bytes ([u8; 32]): {:?}", image_id_bytes);

    let image_id = Digest::from_bytes(image_id_bytes);
    println!("Konvertierte Image ID (Digest): {:?}", image_id);
    println!("Journal Bytes aus dem Receipt: {:?}", export.receipt.journal.bytes);

    match export.receipt.verify(image_id) {
        Ok(_) => {
            println!("✅ Receipt Verifizierung erfolgreich.");
            let journal_value = risc0_zkvm::serde::from_slice::<u32, u8>(&export.receipt.journal.bytes).ok();
            println!("Extrahierter Journal Wert: {:?}", journal_value);
            println!("--- Ende Receipt Verification (Erfolg) ---");
            Ok(VerifyResponse {
                valid: true,
                message: "✅ Receipt ist gültig!".to_string(),
                journal_value,
            })
        }
        Err(e) => {
            println!("❌ Receipt Verifizierung fehlgeschlagen. Fehler: {:?}", e);
            println!("--- Ende Receipt Verification (Fehler) ---");
            Ok(VerifyResponse {
                valid: false,
                message: format!("❌ Receipt ist UNGÜLTIG: {:?}", e),
                journal_value: None,
            })
        }
    }
}

#[tokio::main]
async fn main() {
    // Router erstellen
    let app = Router::new()
        .route("/verify", post(verify_receipt_handler))
        .layer(RequestBodyLimitLayer::new(100 * 1024 * 1024)); // Limit auf 100 MB setzen

    // Server starten
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server läuft auf http://{}", addr);

    // Listener erstellen
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Fehler beim Binden an die Adresse {}: {}", addr, e);
            return;
        }
    };

    // Axum Server starten
    if let Err(e) = axum::serve(listener, app.into_make_service()).await {
        eprintln!("Serverfehler: {}", e);
    }
}