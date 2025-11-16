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
# Use BuildKit cache mounts for faster rebuilds
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch --verbose

# Copy the rest of the application code
COPY . .

# Build release binaries with BuildKit cache mounts
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --bin validator --bin pv

# Copy binaries to a non-cached location (so they're available in next stage)
# Strip binaries to reduce size while copying
RUN --mount=type=cache,target=/app/target \
    mkdir -p /app/binaries && \
    cp target/release/validator /app/binaries/validator && \
    cp target/release/pv /app/binaries/pv && \
    strip /app/binaries/validator /app/binaries/pv 2>/dev/null || true && \
    test -f /app/binaries/validator && test -f /app/binaries/pv

# ============================================================================
# Stage 2: Minimal runtime image
# ============================================================================
FROM debian:bookworm-slim

# Install runtime dependencies and Docker CLI
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    sqlite3 \
    curl \
    gnupg \
    lsb-release \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && apt-get install -y \
    docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
# Add user to docker group to access Docker socket (GID 987 matches host docker group)
RUN groupadd -g 987 docker || true && \
    useradd -m -u 1000 -G docker platform && \
    mkdir -p /app /data && \
    chown -R platform:platform /app /data

# Switch to non-root user
USER platform

WORKDIR /app

# Copy binaries from builder stage (from non-cached location)
COPY --from=builder --chown=platform:platform /app/binaries/validator ./validator
COPY --from=builder --chown=platform:platform /app/binaries/pv ./pv

# Note: config.toml is not required - validator uses environment variables only
# If config.toml is needed in the future, uncomment the line below:
# COPY --chown=platform:platform config.toml ./

# Add binaries to PATH
ENV PATH="/app:${PATH}"

# Expose health check endpoint (if applicable)
EXPOSE 8080 18080

# Default to validator binary
ENTRYPOINT ["./validator"]

