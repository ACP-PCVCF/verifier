FROM rust:1.82
WORKDIR /app
COPY . .
RUN cargo fetch
RUN cargo build --release
ENV RISC0_DEV_MODE=1
CMD ["./target/release/risc0-verify-receipt"]