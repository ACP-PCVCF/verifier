use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:warning=OUT_DIR is {}", std::env::var("OUT_DIR").unwrap_or_default());

    std::fs::create_dir_all("./src/generated_grpc")?;

    tonic_build::configure()
        .out_dir("./src/generated_grpc")
        .compile(
            &["src/receipt_verifier.proto"],
            &["src"],
        )?;

    println!("cargo:rerun-if-changed=src/receipt_verifier.proto");

    Ok(())
}