# ── Stage 1: Build ────────────────────────────────────────
FROM rust:1.83-bookworm AS builder

WORKDIR /app

# Cache dependency build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Build the actual application
COPY src/ src/
COPY migrations/ migrations/
RUN touch src/main.rs src/lib.rs
RUN cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -r vault && useradd -r -g vault -s /bin/false vault

COPY --from=builder /app/target/release/zk-vault /usr/local/bin/zk-vault
COPY --from=builder /app/migrations /app/migrations

USER vault
WORKDIR /app

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/zk-vault", "--version"]

ENTRYPOINT ["zk-vault"]
CMD ["serve"]
