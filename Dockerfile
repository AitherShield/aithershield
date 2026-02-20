# Stage 1: Builder
FROM rust:1.93-bookworm AS builder

# Install any build deps if needed (uncomment/adapt as your project requires)
# RUN apt-get update && apt-get install -y \
#     libssl-dev \
#     pkg-config \
#     && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/aithershield

# Copy manifests first → better layer caching
COPY Cargo.toml Cargo.lock* ./

# Dummy build to cache dependencies (ignores failure if no src yet)
RUN cargo build --release || true

# Now copy source
COPY . .

# Real build — use the ACTUAL binary name from your project
RUN cargo build --release --bin aithershield

# Stage 2: Runtime (slim + secure)
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the correct binary
COPY --from=builder /usr/src/aithershield/target/release/aithershield /app/

# Optional: copy configs, .env, static files, etc.
# COPY config.toml .env* /app/

EXPOSE 8000

# Run as non-root (recommended)
RUN useradd -m appuser
USER appuser

CMD ["/app/aithershield"]
