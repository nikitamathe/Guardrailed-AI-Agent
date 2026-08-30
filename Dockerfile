FROM python:3.12-slim

# --------------------------------------------------------------------------- #
# Guardrailed AI SOC Engine — hardened production image
#   - runs as unprivileged non-root user
#   - least-privilege: only the writable volume dirs are owned by the runtime user
#   - http healthcheck gate
# --------------------------------------------------------------------------- #

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OLLAMA_HOST=http://ollama:11434 \
    # writable paths are redirected onto mounted volumes
    AUDIT_LOG_PATH=/var/lib/guardrailed/audit/audit.log \
    RAG_PERSIST_DIR=/var/lib/guardrailed/index \
    RAG_LOG_FILE=/var/lib/guardrailed/security.log \
    HOME=/var/lib/guardrailed/home \
    HF_HOME=/var/lib/guardrailed/home/.cache/huggingface \
    TRANSFORMERS_CACHE=/var/lib/guardrailed/home/.cache/huggingface

WORKDIR /app

# Create an unprivileged runtime user with a fixed uid/gid.
RUN groupadd --system --gid 10001 guardrail && \
    useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/guardrailed/home --shell /usr/sbin/nologin guardrail && \
    mkdir -p /var/lib/guardrailed/audit /var/lib/guardrailed/index /var/lib/guardrailed/home /var/lib/guardrailed/tmp && \
    chown -R guardrail:guardrail /var/lib/guardrailed && \
    chmod 750 /var/lib/guardrailed

# Install dependencies first (cache layer) before copying code.
COPY requirements.txt ./
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy application code (caches are excluded by .dockerignore).
COPY --chown=guardrail:guardrail . .

# Runtime writable state: audit log, FAISS index, HuggingFace model cache, /tmp.
VOLUME ["/var/lib/guardrailed/audit", "/var/lib/guardrailed/index", "/var/lib/guardrailed/home"]

USER guardrail:guardrail

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
