# Stage 1: build the dashboard frontend.
FROM node:22-alpine AS web
WORKDIR /web
COPY dashboard/web/package.json dashboard/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY dashboard/web/ ./
RUN npm run build

# Stage 2: one image for all Python components (CLI, devices, proxy, dashboard, ...).
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
RUN pip install --no-cache-dir .

COPY config config
COPY --from=web /web/dist /app/dashboard/web/dist

ENTRYPOINT ["bbiot"]
CMD ["--help"]
