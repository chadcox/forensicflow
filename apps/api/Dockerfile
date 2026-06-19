FROM python:3.14-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 unzip \
    && rm -rf /var/lib/apt/lists/*

COPY packages/corvus_core /app/packages/corvus_core
RUN pip install --no-cache-dir /app/packages/corvus_core

COPY apps/api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY apps/api /app/apps/api
ENV PYTHONPATH=/app/apps/api

# Run as a non-root user with a fixed uid shared with the worker so the
# evidence_data and chainsaw rule volumes get consistent ownership on first
# creation (Docker copies the mountpoint owner into a fresh named volume).
RUN groupadd -g 10001 app && useradd -u 10001 -g 10001 -m app \
    && mkdir -p /data/evidence /opt/chainsaw/rules /opt/chainsaw/mappings \
    && chown -R 10001:10001 /data/evidence /opt/chainsaw
USER app

WORKDIR /app/apps/api
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
