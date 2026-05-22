# data-plane/reporting/Dockerfile
# Build context must be data-plane/ (one level up) so we can COPY both
# schemas/ and reporting/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# WeasyPrint native deps + matplotlib font
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 \
        libcairo2 libgdk-pixbuf-2.0-0 \
        libffi-dev shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY reporting /app/reporting
RUN pip install /app/reporting

RUN mkdir -p /data /data/reports

CMD ["intellifim-reporting"]
