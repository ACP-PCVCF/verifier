use anyhow::{Context, Result};
use hex;
use risc0_zkvm::{Digest, Receipt};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct ReceiptExport {
    image_id: String,
    receipt: Receipt,
}

pub fn verify_receipt() -> Result<()> {
    let receipt_path = "receipt_output.json";

    let receipt_data = fs::read_to_string(receipt_path)
        .with_context(|| format!("Konnte Datei '{}' nicht lesen", receipt_path))?;

    let export: ReceiptExport = serde_json::from_str(&receipt_data)
        .context("Deserialisierung des Receipts fehlgeschlagen")?;

    let image_id_vec = hex::decode(&export.image_id)
        .context("Konvertierung der Image-ID in Bytes fehlgeschlagen")?;
    let image_id_bytes: [u8; 32] = image_id_vec.try_into().map_err(|_| {
        anyhow::anyhow!("Die Image-ID hat nicht die erwartete Länge von 32 Bytes")
    })?;
    let image_id = Digest::from_bytes(image_id_bytes);

    // Verifizieren
    match export.receipt.verify(image_id) {
        Ok(_) => {
            println!("✅ Receipt ist gültig!");
            if let Ok(journal_value) = risc0_zkvm::serde::from_slice::<u32, u8>(&export.receipt.journal.bytes) {
                println!("Journal value (u32): {}", journal_value);
            } else {
                println!("Journal bytes (could not decode as u32): {:?}", &export.receipt.journal.bytes);
            }
        }
        Err(e) => {
            println!("❌ Receipt ist UNGÜLTIG: {:?}", e);
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = verify_receipt() {
        eprintln!("Fehler: {}", e);
    }
}