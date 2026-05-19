# data-plane/orchestrator/Dockerfile
# Build context must be data-plane/ (one level up) so we can COPY both
# schemas/ and orchestrator/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY orchestrator /app/orchestrator
RUN pip install /app/orchestrator

# Volume mount target for SQLite; create the dir so the volume mount
# attaches cleanly even on a fresh container.
RUN mkdir -p /data

CMD ["intellifim-orchestrator"]
