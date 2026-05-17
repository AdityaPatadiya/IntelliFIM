# data-plane/correlator/Dockerfile
# Build context must be data-plane/ (one level up) so we can COPY both schemas/
# and correlator/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY correlator /app/correlator
RUN pip install /app/correlator

CMD ["intellifim-correlator"]
