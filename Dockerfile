FROM node:22-bookworm AS frontend-build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm test && npm run build

FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONPATH="/app/services/gateway-api"

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    coreutils \
    curl \
    docker.io \
    git \
    openssh-client \
    procps \
    python3 \
    python3-pip \
    python3-venv \
    tini \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 appuser

WORKDIR /app

COPY requirements.txt /app/
RUN python3 -m venv /opt/venv \
  && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
  && /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

COPY pyproject.toml alembic.ini CHANGELOG.md /app/
COPY services /app/services
COPY app /app/app
COPY configs /app/configs
COPY contracts /app/contracts
COPY openapi /app/openapi
COPY asyncapi /app/asyncapi
COPY schemas /app/schemas
COPY database /app/database
COPY auth /app/auth
COPY scripts /app/scripts
COPY --from=frontend-build /frontend/dist /app/frontend/dist

RUN mkdir -p /workspace /data/ssh /data/command-sessions \
  && touch /data/ssh/known_hosts \
  && chown -R appuser:appuser /workspace /data /app

EXPOSE 8000

USER appuser
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "gateway_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
