# syntax=docker/dockerfile:1
#
# Production image for the VulnTracker Python API (app/). Build from the
# repo root: `docker build -t vulntracker-api .`

FROM python:3.11.10-slim-bookworm@sha256:840e180ebcc6e5c8efab209c43f5e40fd2af98cb49db5c7103c90539c56bb30e AS builder

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt


FROM python:3.11.10-slim-bookworm@sha256:840e180ebcc6e5c8efab209c43f5e40fd2af98cb49db5c7103c90539c56bb30e

# No build tools, no compilers, no pip cache — just the venv built above.
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system appuser \
    && useradd --system --gid appuser --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /data /app \
    && chown appuser:appuser /data /app

WORKDIR /app
COPY --chown=appuser:appuser app/ /app/

# SQLite's default location — separate from the code directory, mountable
# as a volume for persistence (`docker run -v vulntracker-data:/data ...`).
# No secrets set here: SECRET_KEY falls back to a random ephemeral value if
# unset (see app/config.py) so the container is runnable out of the box;
# anything beyond local testing should pass real values via `-e` / a
# secrets manager, never baked into this image.
ENV DATABASE_URL=sqlite:////data/vulntracker.db

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
