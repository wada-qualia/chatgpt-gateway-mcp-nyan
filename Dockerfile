FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONPATH="/app/services/gateway-api:/app/cli"

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    coreutils \
    curl \
    docker.io \
    findutils \
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

COPY requirements.txt pyproject.toml /app/
RUN python3 -m venv /opt/venv \
  && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
  && /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

COPY services /app/services
COPY cli /app/cli
COPY app /app/app
COPY configs /app/configs
COPY openapi /app/openapi
COPY asyncapi /app/asyncapi
COPY schemas /app/schemas
COPY galaxy.project.yaml /app/galaxy.project.yaml

RUN mkdir -p /workspace /data /auth \
  && chown -R appuser:appuser /workspace /data /auth /app

USER appuser

EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "gateway_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
