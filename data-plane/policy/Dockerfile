# data-plane/policy/Dockerfile
# Build context must be data-plane/ (one level up) so we can COPY both
# schemas/ and policy/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY policy /app/policy
RUN pip install /app/policy

CMD ["intellifim-policy-engine"]
