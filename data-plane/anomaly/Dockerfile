# data-plane/anomaly/Dockerfile
# Build context must be data-plane/ (one level up) so we can COPY both
# schemas/ and anomaly/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY anomaly /app/anomaly
RUN pip install /app/anomaly

# Bake the trained model into the image so deployment is atomic.
# Image version === model version.
RUN python -m anomaly.train \
    --input /app/anomaly/training-data/baseline-events.jsonl \
    --output /app/model.pkl

CMD ["intellifim-anomaly-detector"]
