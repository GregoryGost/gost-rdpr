#
# Combined Dockerfile for GOST-RDPR Python Backend + Vue UI
# 
# This Dockerfile should be placed in the Python repository (gost-rdpr)
# It clones the UI from https://github.com/GregoryGost/gost-rdpr-ui
#
# Build arguments:
#   UI_REPO_URL - UI repository URL (default: https://github.com/GregoryGost/gost-rdpr-ui.git)
#   UI_BRANCH - UI branch to clone (default: main)
#   PYTHON_VERSION - Python base image version (default: 3.14-slim-trixie)
#   NODE_VERSION - Node.js base image version (default: 24.13-alpine)
#
# Note: Nginx is installed from Debian repositories (python:slim-trixie is Debian-based)
#

ARG PYTHON_VERSION=3.14-slim-trixie
ARG NODE_VERSION=24.13-alpine

########################################################################################################################
# UI BUILDER (Node.js + Vue 3)
########################################################################################################################
FROM node:${NODE_VERSION} AS ui-builder

# Fix OOM kill Docker with build
ENV NODE_OPTIONS="--max-old-space-size=8192"

WORKDIR /ui

# Install git for cloning
RUN apk add --no-cache git

# Clone UI repository
ARG BRANCH=main
RUN git clone --depth 1 --branch ${BRANCH} https://github.com/GregoryGost/gost-rdpr-ui.git .

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# Install dependencies
RUN pnpm install --frozen-lockfile

# Build production version of UI (without type-check to avoid OOM in Docker)
RUN pnpm build:docker

########################################################################################################################
# PYTHON BUILDER (Poetry + Dependencies)
########################################################################################################################
FROM python:${PYTHON_VERSION} AS python-builder

ENV DEBIAN_FRONTEND="noninteractive"

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  build-essential \
  curl \
  libpq-dev \
  pkg-config

WORKDIR /app

# Copy Python application from current directory (gost-rdpr repository)
COPY poetry.lock pyproject.toml LICENSE ./

# Install Poetry and dependencies
ARG POETRY_VERSION=2.3.4
RUN pip install poetry==${POETRY_VERSION} --no-cache --root-user-action=ignore \
  && poetry config virtualenvs.in-project true \
  && poetry install --no-interaction --no-cache

########################################################################################################################
# FINAL APPLICATION IMAGE
# BASED on PYTHON (Debian)
########################################################################################################################
FROM python:${PYTHON_VERSION}

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install runtime dependencies including nginx and supervisor
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  net-tools \
  libpq5 \
  curl \
  nginx \
  supervisor \
  && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

WORKDIR /app

# Copy Python application and dependencies
COPY --from=python-builder /app ./

# Copy Python source code from current directory
COPY . .

# Copy built UI to nginx directory
COPY --from=ui-builder /ui/dist /var/www/html

# Copy configuration files
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker/entrypoint.sh /entrypoint.sh

# Set execute permissions
RUN chmod +x /entrypoint.sh

# Expose ports
# 8080 - Nginx (Web UI + API proxy)
# 4000 - Python API (direct access for external applications)
#EXPOSE 8080 4000

# Health check via nginx
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://127.0.0.1/api/health || exit 1

# Start via entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
