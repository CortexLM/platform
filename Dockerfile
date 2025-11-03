# Multi-stage Dockerfile for Platform Validator
# Optimized for fast builds and small final image

# ============================================================================
# Stage 1: Builder with full Rust toolchain
# ============================================================================
FROM rust:1.90-slim AS builder

# Install system dependencies for build
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./

# Copy all crates and bins for dependency resolution
COPY crates ./crates
COPY bins ./bins

# Build dependencies only (layer caching optimization)
RUN cargo fetch --verbose

# Copy the rest of the application code
COPY . .

# Build release binaries
RUN cargo build --release --bin validator --bin pv

# Strip binaries to reduce size
RUN strip target/release/validator target/release/pv

# ============================================================================
# Stage 2: Minimal runtime image
# ============================================================================
FROM debian:bookworm-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 platform && \
    mkdir -p /app /data && \
    chown -R platform:platform /app /data

# Switch to non-root user
USER platform

WORKDIR /app

# Copy binaries from builder stage
COPY --from=builder --chown=platform:platform /app/target/release/validator ./validator
COPY --from=builder --chown=platform:platform /app/target/release/pv ./pv

# Copy config file
COPY --chown=platform:platform config.toml ./

# Add binaries to PATH
ENV PATH="/app:${PATH}"

# Expose health check endpoint (if applicable)
EXPOSE 8080 18080

# Default to validator binary
ENTRYPOINT ["./validator"]

