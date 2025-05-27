# How to Rust

Build:
```
cargo clean && cargo build 
```
Run:
```
cargo run
```

# How to Docker (not fixed)

Build:
```
docker build -t risc0-verify-receipt .   
```
Run:
```
docker run risc0-verify-receipt
```
Change verifing mode in ./Dockerfile:
```
ENV RISC0_DEV_MODE=1
```
