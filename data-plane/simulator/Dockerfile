# data-plane/simulator/Dockerfile
# Build context must be data-plane/ (one level up) so we can COPY both
# schemas/ and simulator/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl dnsutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY simulator /app/simulator
RUN pip install /app/simulator

ENTRYPOINT ["intellifim-simulator"]
CMD ["--help"]
