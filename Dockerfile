FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY python/ /app/python/
RUN pip install "/app/python[server]" && useradd --system --uid 10001 guardrail && mkdir -p /data /config \
    && chown guardrail /data

COPY config/guardrail.example.yaml /config/guardrail.yaml

USER guardrail
ENV GUARDRAIL_CONFIG=/config/guardrail.yaml
EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"
CMD ["guardrail-rag-jev", "serve", "--host", "0.0.0.0", "--port", "8080"]
