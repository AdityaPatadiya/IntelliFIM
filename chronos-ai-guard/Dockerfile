# syntax=docker/dockerfile:1.6

# =============================================================================
# Frontend image with two targets:
#   - dev:  Vite dev server with hot reload (used by docker-compose.yml)
#   - prod: nginx serving the built static bundle (docker-compose.prod.yml)
# =============================================================================

# ---------- Dev: Vite dev server ----------
FROM node:20-alpine AS dev

WORKDIR /app

# Lock-aware install so cache invalidates correctly.
COPY package.json package-lock.json* bun.lockb* ./
RUN if [ -f package-lock.json ]; then \
        npm ci --no-audit --no-fund; \
    else \
        npm install --no-audit --no-fund; \
    fi

# Source comes in as a bind-mount in dev (compose volumes), so we don't
# COPY it here — keeps rebuilds fast when only deps change.

EXPOSE 8080
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "8080"]


# ---------- Build stage for prod (creates static bundle) ----------
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json* bun.lockb* ./
RUN if [ -f package-lock.json ]; then \
        npm ci --no-audit --no-fund; \
    else \
        npm install --no-audit --no-fund; \
    fi

COPY . .

# In prod we serve everything (HTML + API) from the same origin via nginx,
# so the API base URL is empty (relative paths). Override via build arg if
# the API is on a different host.
ARG VITE_API_URL=
ENV VITE_API_URL=${VITE_API_URL}

RUN npm run build


# ---------- Prod: nginx serves the built bundle and proxies the API ----------
FROM nginx:1.27-alpine AS prod

# Drop the default site, install ours.
RUN rm -f /etc/nginx/conf.d/default.conf

COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
