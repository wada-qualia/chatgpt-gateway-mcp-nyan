FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv python3-pip bash coreutils findutils git curl ca-certificates tini procps && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 appuser

WORKDIR /app

RUN mkdir -p /app/scripts

COPY requirements.txt /app/requirements.txt

RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir --upgrade pip && /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY scripts/create_user.py /app/scripts/create_user.py

RUN mkdir -p /workspace /auth /app/scripts && chown -R appuser:appuser /workspace /auth /app

USER appuser

EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "/app/app/server.py"]
