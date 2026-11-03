# One image for all Python components (CLI, devices, hub, directory, ...).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BBIOT_CONFIG=/app/config/home.yaml \
    BBIOT_SECRETS_DIR=/app/secrets

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
RUN pip install --no-cache-dir .

COPY config config

ENTRYPOINT ["bbiot"]
CMD ["--help"]
