
# RedAgent API — Starlette/uvicorn service that shells out to security scanners.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# System scanners used by black-box mode (nmap, nikto, sqlmap) plus the Go
# toolchain to install nuclei, and build/runtime basics.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        nikto \
        sqlmap \
        golang-go \
        ca-certificates \
        git \
        curl \
    && rm -rf /var/lib/apt/lists/*

# nuclei (Go) — installed into /root/go/bin, already on PATH above.
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && nuclei -update-templates || true

WORKDIR /app

# Python deps first for layer caching.
COPY pyproject.toml README.md ./
RUN pip install --upgrade pip \
    && pip install PyYAML uvicorn starlette anyio

# Application code.
COPY . .
RUN pip install -e .

EXPOSE 8000

CMD ["python", "serve_api.py"]
