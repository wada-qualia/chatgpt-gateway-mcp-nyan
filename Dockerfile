FROM node:22-bookworm AS frontend-build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm test && npm run build

FROM ubuntu:24.04 AS runtime-base

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

COPY requirements.txt /app/
RUN python3 -m venv /opt/venv \
  && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
  && /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

COPY pyproject.toml alembic.ini /app/
COPY .dockerignore /app/.dockerignore
COPY vendor/llm-usage-sdk /app/vendor/llm-usage-sdk
COPY vendor/affine-sdk /app/vendor/affine-sdk
COPY scripts/python_sdk_artifact.py /app/scripts/python_sdk_artifact.py
COPY scripts/verify_lup_sdk_artifact.py /app/scripts/verify_lup_sdk_artifact.py
COPY scripts/verify_affine_sdk_artifact.py /app/scripts/verify_affine_sdk_artifact.py
RUN /opt/venv/bin/python /app/scripts/verify_lup_sdk_artifact.py \
  && /opt/venv/bin/python /app/scripts/verify_affine_sdk_artifact.py \
  && /opt/venv/bin/pip install --no-cache-dir --no-deps \
    /app/vendor/llm-usage-sdk/klab_llm_usage-0.1.0b2-py3-none-any.whl \
    /app/vendor/affine-sdk/affine_py_sdk-0.6.0-py3-none-any.whl \
  && /opt/venv/bin/python -c 'import klab_llm_usage as sdk; from affine_py_sdk import AffineBridgeClient, AffineGlobalDocumentContent; assert sdk.__version__ == "0.1.0b2"; assert AffineBridgeClient.__name__ == "AffineBridgeClient"; assert AffineGlobalDocumentContent.__name__ == "AffineGlobalDocumentContent"; assert all(hasattr(AffineBridgeClient, name) for name in ("trash_affine_document", "restore_affine_document", "purge_affine_document"))'

COPY services /app/services
COPY cli /app/cli
COPY scripts /app/scripts
COPY app /app/app
COPY configs /app/configs
COPY contracts /app/contracts
COPY docs/contracts /app/docs/contracts
COPY openapi /app/openapi
COPY asyncapi /app/asyncapi
COPY schemas /app/schemas
COPY database /app/database
COPY galaxy.project.yaml /app/galaxy.project.yaml
COPY deploy/gateway_known_hosts /etc/gateway/ssh_known_hosts
COPY --from=frontend-build /frontend/dist /app/frontend/dist

RUN chmod 444 /etc/gateway/ssh_known_hosts \
  && mkdir -p /workspace /data /auth \
  && chown -R appuser:appuser /workspace /data /auth /app

EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "gateway_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

FROM runtime-base AS test

USER root
RUN apt-get update \
  && apt-get install -y --no-install-recommends jq \
  && rm -rf /var/lib/apt/lists/*
COPY requirements-dev.txt /app/
COPY --chown=appuser:appuser packaging /app/packaging
COPY --chown=appuser:appuser deploy /app/deploy
COPY --chown=appuser:appuser .gitlab-ci.yml /app/.gitlab-ci.yml
COPY --chown=appuser:appuser Dockerfile /app/Dockerfile
COPY --chown=appuser:appuser Jenkinsfile /app/Jenkinsfile
RUN /opt/venv/bin/pip install --no-cache-dir -r /app/requirements-dev.txt
USER appuser
RUN PYTHONPATH=/app/services/gateway-api /opt/venv/bin/python \
      /app/scripts/calibrate_lup_final_response_estimator.py \
      /app/configs/lup/final-response-calibration-v1.json
RUN mkdir -p /app/artifacts/evaluation \
  && PYTHONPATH=/app/services/gateway-api /opt/venv/bin/python \
      /app/scripts/run_mcp_federation_evaluation.py \
      --config /app/configs/mcp-federation/phase-9-evaluation.json \
      --output /app/artifacts/evaluation/phase-9-evaluation-report.json
RUN pytest /app/services/gateway-api/tests /app/cli/tests

FROM runtime-base AS production

USER appuser
