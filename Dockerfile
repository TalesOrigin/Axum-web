# syntax=docker/dockerfile:1.7
FROM rust:1.80-bookworm AS builder
WORKDIR /app

COPY Cargo.toml ./
COPY src ./src
COPY migrations ./migrations
COPY static ./static
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 axumweb

WORKDIR /app
COPY --from=builder /app/target/release/axum-web /usr/local/bin/axum-web
COPY --from=builder /app/migrations ./migrations
COPY --from=builder /app/static ./static

USER axumweb
EXPOSE 3000
ENV HTTP_ADDR=0.0.0.0:3000 \
    APP_ENV=production \
    LOG_FORMAT=json \
    RUN_MIGRATIONS=true

HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -fsS http://127.0.0.1:3000/health/ready || exit 1
CMD ["/usr/local/bin/axum-web"]
