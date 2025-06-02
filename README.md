# How to Rust

Build:
```
cargo clean && cargo build 
```
Run:
```
cargo run
```

# How to Docker

Build:
```
docker build -t verifier .   
```
Run:
```
docker run -d -p 50051:50051 -p 3000:3000 --name verifier verifier
```
