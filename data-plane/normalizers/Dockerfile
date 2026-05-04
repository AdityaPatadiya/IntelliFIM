# data-plane/normalizers/Dockerfile
# Build context must be the data-plane/ directory so we can COPY both
# schemas/ and normalizers/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install schemas first (its source rarely changes), then normalizers.
COPY schemas /app/schemas
RUN pip install /app/schemas

COPY normalizers /app/normalizers
RUN pip install /app/normalizers

# Source is selected at runtime; image is identical for all six.
CMD ["intellifim-normalizer"]
