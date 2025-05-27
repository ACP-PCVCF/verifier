# Stage 1: Builder

FROM rust:1.82 AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {println!(\"Dummy main for dep build\");}" > src/main.rs
RUN cargo build --release
RUN rm -rf src
COPY src ./src
COPY build.rs ./build.rs
RUN cargo build --release

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/risc0-verify-receipt .
ENV RISC0_DEV_MODE=0
CMD ["./risc0-verify-receipt"]