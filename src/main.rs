use anyhow::{Context, Result};
use hex;
use risc0_zkvm::{Digest, Receipt};
use std::net::SocketAddr;
use tokio_stream::StreamExt;
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, pkcs1v15::Pkcs1v15Sign};
use sha2::{Sha256, Digest as Sha2DigestTrait};
use base64::{engine::general_purpose, Engine as _};
use const_oid::AssociatedOid;
use pkcs1::ObjectIdentifier;
use digest::{
    self,
    Digest as DigestTrait,
    OutputSizeUser,
    Reset,
    FixedOutputReset,
    generic_array::GenericArray,
    FixedOutput,
    Update
};
use bincode;
use serde_json;

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

#[derive(serde::Deserialize, Debug)]
struct GrpcRequestPayload {
    image_id: String,
    receipt: String,
}

#[derive(serde::Serialize, Debug)]
struct AppResponse {
valid: bool,
    message: String,
    journal_value: Option<f64>,
}

#[derive(Default, Clone)]
struct Sha256WithOid(Sha256);

impl AssociatedOid for Sha256WithOid {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
}

impl OutputSizeUser for Sha256WithOid {
    type OutputSize = <Sha256 as OutputSizeUser>::OutputSize;
}

impl Update for Sha256WithOid {
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.0, data);
    }
}

impl FixedOutput for Sha256WithOid {
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        FixedOutput::finalize_into(self.0, out);
    }
}

impl Reset for Sha256WithOid {
    fn reset(&mut self) {
        Reset::reset(&mut self.0);
    }
}

impl FixedOutputReset for Sha256WithOid {
     fn finalize_fixed_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        FixedOutputReset::finalize_fixed_reset(&mut self.0)
     }
     fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        FixedOutputReset::finalize_into_reset(&mut self.0, out);
     }
}

impl DigestTrait for Sha256WithOid {
    fn new() -> Self {
        Sha256WithOid(Sha256::new())
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        Update::update(self, data.as_ref());
    }

    fn finalize(self) -> GenericArray<u8, Self::OutputSize> {
        DigestTrait::finalize(self.0)
    }

    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
        Sha256WithOid(Sha256::new_with_prefix(data))
    }

    fn chain_update(self, data: impl AsRef<[u8]>) -> Self {
         Sha256WithOid(self.0.chain_update(data))
    }

    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        DigestTrait::finalize_into(self.0, out);
    }

    fn finalize_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        DigestTrait::finalize_reset(&mut self.0)
    }

    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        DigestTrait::finalize_into_reset(&mut self.0, out);
    }

    fn reset(&mut self) {
        Reset::reset(&mut self.0);
    }

    fn output_size() -> usize {
        <Sha256 as DigestTrait>::output_size()
    }

    fn digest(data: impl AsRef<[u8]>) -> GenericArray<u8, Self::OutputSize> {
        <Sha256 as DigestTrait>::digest(data)
    }
}


async fn verify_signature(commitment: &str, signed_sensor_data: &str, sensorkey: &str) -> bool {
    let payload = &commitment;
    let signature_b64 = &signed_sensor_data;
    let public_key_pem = &sensorkey;

    println!("Payload: {}", payload);
    println!("Signature: {}", signature_b64);
    println!("Public Key PEM: {}", public_key_pem);

    let public_key = match RsaPublicKey::from_public_key_pem(public_key_pem) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("Fehler beim Laden des Public Keys (SPKI erwartet): {:?}", e);
            match RsaPublicKey::from_pkcs1_pem(public_key_pem) {
                Ok(pk_fallback) => {
                    eprintln!("Warnung: Public Key wurde als PKCS#1 geladen, SPKI wird bevorzugt.");
                    pk_fallback
                },
                Err(e_fallback) => {
                    eprintln!("Fehler beim Laden des Public Keys auch als PKCS#1: {:?}", e_fallback);
                    return false;
                }
            }
        }
    };

    let mut hasher = Sha256::new();
    Update::update(&mut hasher, payload.as_bytes());
    let digest_val = hasher.finalize();

    let signature = match general_purpose::STANDARD.decode(signature_b64) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("Fehler beim Dekodieren der Signatur: {:?}", e);
            return false;
        }
    };

    let padding = Pkcs1v15Sign::new::<Sha256WithOid>();
    match public_key.verify(padding, &digest_val, &signature) {
        Ok(_) => {
            println!("Signatur ist gültig.");
            true
        }
        Err(e) => {
            eprintln!("Verifikation fehlgeschlagen: {:?}", e);
            false
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy)]
pub struct GuestMetrics {
    pub start_cycles: u64,
    pub end_cycles: u64,
    pub risc_v_cycles: u64,
}

async fn verify_receipt_logic(export: ReceiptExport) -> Result<AppResponse> {
    println!("--- Start Receipt Verification (Logic) ---");
    println!("Empfangene Image ID (String): {}", export.image_id);

    #[derive(serde::Deserialize)]
    struct SignatureForHost {
        commitment: String,
        signature: String,
        pub_key: String,
    }

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

            let (journal_value, serialized_signatures) =
                match risc0_zkvm::serde::from_slice::<(f64, Vec<u8>), _>(&export.receipt.journal.bytes) {
                    Ok((val, serialized_sigs)) => (Some(val), Some(serialized_sigs)),
                    Err(e) => {
                        let msg = format!("Journal konnte nicht als (f64, Vec<u8>) deserialisiert werden: {:?}", e);
                        println!("Warnung: {}. Journal Bytes: {:?}", msg, export.receipt.journal.bytes);
                        return Ok(AppResponse {
                            valid: false,
                            message: format!("❌ Journal Deserialisierung fehlgeschlagen: {}", msg),
                            journal_value: None,
                        });
                    }
                };

            let signature_data_list: Vec<SignatureForHost> = match bincode::deserialize(&serialized_signatures.unwrap()) {
                Ok(list) => list,
                Err(e) => {
                    let msg = format!("Fehler beim Bincode-Deserialisieren der Signaturliste: {:?}", e);
                    eprintln!("{}", msg);
                    return Ok(AppResponse { valid: false, message: msg, journal_value });
                }
            };

            let mut all_signatures_valid = true;
            if signature_data_list.is_empty() {
                println!("Warnung: Keine Signaturen vom Guest erhalten.");
                all_signatures_valid = false;
            } else {
                for (i, signature_data) in signature_data_list.iter().enumerate() {
                    println!("--- Verifiziere Signatur {}/{} ---", i + 1, signature_data_list.len());
                    if !verify_signature(&signature_data.commitment, &signature_data.signature, &signature_data.pub_key).await {
                        all_signatures_valid = false; // Fehler wird bereits in verify_signature gedruckt
                    }
                }
            }

            if all_signatures_valid {
                println!("✅ Alle Signaturen erfolgreich verifiziert!");
                println!("Extrahierter Journal Wert: {:?}", journal_value.as_ref().unwrap());
                println!("--- Ende Receipt Verification (Logic - Erfolg) ---");
                Ok(AppResponse {
                    valid: true,
                    message: "✅ Receipt und alle Signaturen sind gültig!".to_string(),
                    journal_value,
                })
            } else {
                eprintln!("❌ Mindestens eine Signatur war ungültig.");
                Ok(AppResponse {
                    valid: false,
                    message: "❌ Receipt ist gültig, aber mindestens eine Signatur war ungültig.".to_string(),
                    journal_value,
                })
            }
        }
        Err(e) => {
            println!("❌ Receipt Verifizierung fehlgeschlagen. Fehler: {:?}", e);
            println!("--- Ende Receipt Verification (Logic - Fehler) ---");
            Ok(AppResponse {
                valid: false,
                message: format!("❌ Receipt ist UNGÜLTIG: {:?}", e),
                journal_value: None,
            })
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

        let request_payload: GrpcRequestPayload = match serde_json::from_slice(&received_bytes) {
            Ok(payload) => payload,
            Err(e) => {
                eprintln!("gRPC: Fehler beim Deserialisieren der JSON-Payload: {:?}", e);
                return Err(tonic::Status::invalid_argument(format!(
                    "Ungültige JSON-Payload: {}",
                    e
                )));
            }
        };

        let decoded_bytes = match general_purpose::STANDARD.decode(&request_payload.receipt) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("gRPC: Fehler beim Dekodieren von Base64 aus dem 'receipt'-Feld: {:?}", e);
                return Err(tonic::Status::invalid_argument(format!(
                    "Ungültige Base64-Daten im 'receipt'-Feld: {}",
                    e
                )));
            }
        };
        println!("gRPC: Base64-dekodierte Datenlänge: {}.", decoded_bytes.len());

        let receipt: Receipt = match bincode::deserialize(&decoded_bytes) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("gRPC: Fehler beim Deserialisieren des Receipts mit Bincode: {:?}", e);
                return Err(tonic::Status::invalid_argument(format!(
                    "Ungültige Bincode-Daten für Receipt: {}",
                    e
                )));
            }
        };

        let payload = ReceiptExport {
            image_id: request_payload.image_id,
            receipt,
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
    if std::env::var("RISC0_DEV_MODE").unwrap_or_default() != "0" {
        println!("Warnung: Server startet im RISC0_DEV_MODE. In diesem Modus werden keine echten ZK-Beweise verifiziert. Nur für Testzwecke geeignet.");
    } else {
        println!("Info: Server startet im Produktivmodus (RISC0_DEV_MODE=0).");
    }

    let tonic_addr = SocketAddr::from(([0, 0, 0, 0], 50051));
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

    let _ = tokio::join!(grpc_server_task);
    Ok(())
}