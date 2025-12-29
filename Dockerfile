#
# BUILDER
#
FROM python:3.14.2-slim-trixie AS builder

ENV DEBIAN_FRONTEND="noninteractive"

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  build-essential \
  curl \
  libpq-dev \
  pkg-config \
  net-tools \
  htop \
  libpam-modules \
  libpam-modules-bin

WORKDIR /poetry
COPY poetry.lock pyproject.toml LICENSE ./

RUN pip install poetry==2.2.1 --no-cache --root-user-action=ignore \
  && poetry config virtualenvs.in-project true \
  && poetry install --no-interaction --no-cache

#
# APPLICATION
#
FROM python:3.14.2-slim-trixie

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /app

COPY --from=builder /poetry ./

RUN rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

# see .dockerignore if you dont want to copy all
COPY . .

CMD ["/app/.venv/bin/python", "-u", "/app/main.py"]
