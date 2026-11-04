# Stage 1: build the dashboard frontend.
FROM node:22-alpine AS web
WORKDIR /web
COPY dashboard/web/package.json dashboard/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY dashboard/web/ ./
RUN npm run build

# Stage 2: the MLS sidecar (OpenMLS), as a static musl binary.
FROM rust:1.91-alpine AS mls
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY mls-sidecar/Cargo.toml mls-sidecar/Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release --locked && rm -rf src
COPY mls-sidecar/src src
RUN touch src/main.rs && cargo build --release --locked && strip target/release/bbiot-mls

# Stage 3: one image for all Python components (CLI, devices, proxy, dashboard, ...).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BBIOT_CONFIG=/app/config/home.yaml \
    BBIOT_SECRETS_DIR=/app/secrets \
    BBIOT_DASHBOARD_STATIC=/app/dashboard/web/dist

WORKDIR /app
COPY pyproject.toml README.md ./
COPY securelib securelib
COPY cli cli
COPY devices devices
COPY hub hub
COPY directory directory
COPY translog translog
COPY rootca rootca
COPY dashboard dashboard
COPY bench bench
COPY evilbroker evilbroker
COPY kdc kdc
RUN pip install --no-cache-dir ".[bench]"

COPY config config
COPY --from=web /web/dist /app/dashboard/web/dist
COPY --from=mls /src/target/release/bbiot-mls /usr/local/bin/bbiot-mls

ENTRYPOINT ["bbiot"]
CMD ["--help"]
