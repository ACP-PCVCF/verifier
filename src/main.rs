use axum::{
    extract::Json as AxumJson,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use anyhow::{Context, Result};
use hex;
use risc0_zkvm::Digest;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tower_http::limit::RequestBodyLimitLayer;

// Stattdessen:
mod generated_grpc {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/generated_grpc/receipt_verifier.rs"));
}
use generated_grpc::{
    receipt_verifier_service_server::{ReceiptVerifierService, ReceiptVerifierServiceServer},
    BytesChunk, GrpcVerifyResponse,
};

#[derive(serde::Deserialize, serde::Serialize, Debug)]
struct ReceiptExport {
    image_id: String,
    receipt: risc0_zkvm::Receipt,
}

#[derive(serde::Serialize, Debug)]
struct AppResponse {
    valid: bool,
    message: String,
    journal_value: Option<u32>,
}

async fn verify_receipt_logic(export: ReceiptExport) -> Result<AppResponse> {
    println!("--- Start Receipt Verification (Logic) ---");
    println!("Empfangene Image ID (String): {}", export.image_id);

    let image_id_vec = hex::decode(&export.image_id)
        .context("Konvertierung der Image-ID von Hex zu Bytes fehlgeschlagen")?;

    let image_id_bytes: [u8; 32] = image_id_vec.try_into().map_err(|e_vec: Vec<u8>| {
        println!("Fehler bei try_into für Image ID: Vec Länge {}", e_vec.len());
        anyhow::anyhow!("Die Image-ID hat nicht die erwartete Länge von 32 Bytes. Erhalten: {} Bytes.", e_vec.len())
    })?;

    let image_id_digest = Digest::from(image_id_bytes);

    match export.receipt.verify(image_id_digest) {
        Ok(_) => {
            println!("✅ Receipt Verifizierung erfolgreich.");
            let journal_value = match risc0_zkvm::serde::from_slice::<u32, u8>(&export.receipt.journal.bytes) {
                Ok(val) => Some(val),
                Err(e) => {
                    println!("Warnung: Journal konnte nicht als u32 deserialisiert werden: {:?}. Journal Bytes: {:?}", e, export.receipt.journal.bytes);
                    None
                }
            };
            println!("Extrahierter Journal Wert: {:?}", journal_value);
            println!("--- Ende Receipt Verification (Logic - Erfolg) ---");
            Ok(AppResponse {
                valid: true,
                message: "✅ Receipt ist gültig!".to_string(),
                journal_value,
            })
        }
        Err(e) => {
            println!("❌ Receipt Verifizierung fehlgeschlagen. Fehler: {:?}", e);
            println!("--- Ende Receipt Verification (Logic - Fehler) ---");
            // Es ist besser, hier auch einen Ok-Typ zurückzugeben, der den Fehlerzustand anzeigt,
            // anstatt die Funktion mit einem Err abstürzen zu lassen, wenn der Handler dies nicht erwartet.
            Ok(AppResponse {
                valid: false,
                message: format!("❌ Receipt ist UNGÜLTIG: {:?}", e),
                journal_value: None,
            })
        }
    }
}

async fn verify_receipt_handler(
    AxumJson(payload): AxumJson<ReceiptExport>,
) -> impl IntoResponse {
    println!("HTTP-Handler: Verifizierung für Payload: {:?}", payload);
    match verify_receipt_logic(payload).await {
        Ok(app_response) => {
            if app_response.valid {
                (StatusCode::OK, AxumJson(app_response))
            } else {
                // Sie könnten hier einen anderen Statuscode für ungültige Receipts verwenden, z.B. BAD_REQUEST
                (StatusCode::BAD_REQUEST, AxumJson(app_response))
            }
        }
        Err(e) => {
            // Interner Serverfehler, wenn die Logik selbst fehlschlägt (nicht die Receipt-Verifizierung)
            eprintln!("Fehler in verify_receipt_logic: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(AppResponse { // Stellen Sie sicher, dass AppResponse hier serialisierbar ist
                    valid: false,
                    message: format!("Interner Serverfehler: {}", e),
                    journal_value: None,
                }),
            )
        }
    }
}

#[derive(Default)]
pub struct MyGrpcReceiptVerifier;

#[tonic::async_trait]
impl ReceiptVerifierService for MyGrpcReceiptVerifier { 
    async fn verify_receipt_stream(
        &self,
        request: tonic::Request<tonic::Streaming<BytesChunk>>,
    ) -> Result<tonic::Response<GrpcVerifyResponse>, tonic::Status> {
        println!("--- Start gRPC Receipt Verification Stream ---");
        let mut stream = request.into_inner();
        let mut received_bytes = Vec::new();

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    received_bytes.extend_from_slice(&chunk.data);
                }
                Err(err) => {
                    eprintln!("Fehler beim Empfangen eines Chunks im Stream: {:?}", err);
                    return Err(tonic::Status::internal(format!(
                        "Stream-Fehler: {}",
                        err
                    )));
                }
            }
        }
        println!("gRPC: Insgesamt {} Bytes empfangen.", received_bytes.len());

        let payload: ReceiptExport = match serde_json::from_slice(&received_bytes) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("gRPC: Fehler beim Deserialisieren von JSON: {:?}", e);
                return Err(tonic::Status::invalid_argument(format!(
                    "Ungültige JSON-Daten: {}",
                    e
                )));
            }
        };

        match verify_receipt_logic(payload).await {
            Ok(app_response) => {
                let grpc_response = GrpcVerifyResponse {
                    valid: app_response.valid,
                    message: app_response.message,
                    journal_value: app_response.journal_value,
                };
                println!("--- Ende gRPC Receipt Verification (Erfolg) ---");
                Ok(tonic::Response::new(grpc_response))
            }
            Err(e) => {
                eprintln!("gRPC: Fehler in verify_receipt_logic: {:?}", e);
                Err(tonic::Status::internal(format!(
                    "Fehler bei der Verifizierungslogik: {}",
                    e
                )))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //let axum_addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    //let tonic_addr = SocketAddr::from(([127, 0, 0, 1], 50051));
    let axum_addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let tonic_addr = SocketAddr::from(([0, 0, 0, 0], 50051));

    let http_router = Router::new()
        .route("/verify", post(verify_receipt_handler))
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 5));

    let http_server_task = tokio::spawn(async move {
        let listener = TcpListener::bind(axum_addr).await.unwrap();
        println!("Axum HTTP Server läuft auf http://{}", axum_addr);
        axum::serve(listener, http_router.into_make_service()).await.unwrap();
    });

    let grpc_service_impl = MyGrpcReceiptVerifier::default();
    let tonic_service_server = ReceiptVerifierServiceServer::new(grpc_service_impl);

    let grpc_server_task = tokio::spawn(async move {
        println!("Tonic gRPC Server läuft auf http://{}", tonic_addr);
        if let Err(e) = tonic::transport::Server::builder()
            .add_service(tonic_service_server)
            .serve(tonic_addr)
            .await
        {
            eprintln!("Fehler beim Starten des gRPC-Servers: {:?}", e);
        }
    });

    let _ = tokio::try_join!(http_server_task, grpc_server_task);
    Ok(())
}