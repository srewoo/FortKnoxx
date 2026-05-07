# FortKnoxx backend image.
# Two-stage: builder installs deps into a venv, runtime copies the venv only.
# Keeps the final image lean and avoids shipping build toolchains.

FROM python:3.11-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements-base.txt requirements-ml.txt requirements.txt constraints.txt* ./
RUN pip install --upgrade pip wheel "setuptools<82" \
    && pip install "numpy<2" \
    && (pip install -r requirements.txt -c constraints.txt 2>/dev/null \
        || pip install -r requirements.txt --use-deprecated=legacy-resolver)


FROM python:3.11-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Runtime tools: git for repo cloning, docker CLI for ZAP DAST + Trivy invocations.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates docker.io \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 fortknoxx

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY . .

RUN chown -R fortknoxx:fortknoxx /app
USER fortknoxx

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
