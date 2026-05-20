# data-plane/auth_backend/Dockerfile
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY auth_backend /app/auth_backend
RUN pip install /app/auth_backend

RUN mkdir -p /data

CMD ["intellifim-auth-backend"]
