# Fula Mail - Decentralized Email Gateway
# Multi-stage build for minimal image size

# ============================================
# Stage 1: Build
# ============================================
FROM rust:1.85-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build release binary with reduced parallelism for low-memory systems
ENV CARGO_BUILD_JOBS=2
RUN cargo build --release

# ============================================
# Stage 2: Runtime
# ============================================
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/fula-mail /usr/local/bin/fula-mail

# Copy migrations
COPY migrations /app/migrations

# Create non-root user and data directory
RUN useradd -r -s /bin/false fulamail && \
    mkdir -p /var/lib/fula-mail && \
    chown fulamail:fulamail /var/lib/fula-mail
USER fulamail

# SMTP, Submission, IMAP, JMAP, HTTP API
EXPOSE 25 587 993 443 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Environment defaults
ENV RUST_LOG=info
ENV MAIL_HOST=0.0.0.0
ENV MAIL_HTTP_PORT=8080
ENV MAIL_SMTP_PORT=25
ENV MAIL_SUBMISSION_PORT=587
ENV MAIL_IMAP_PORT=993

# Database (shared PostgreSQL - same instance as pinning-service/fula-api)
ENV POSTGRES_HOST=postgres
ENV POSTGRES_PORT=5432
ENV POSTGRES_DB=pinning_service
ENV POSTGRES_USER=pinning_user

# Pinning service integration
ENV PINNING_SERVICE_URL=http://localhost:6000

ENTRYPOINT ["fula-mail"]
CMD []
