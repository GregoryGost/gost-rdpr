FROM python:3.13-slim-bookworm

ARG IS_PRODUCTION
ARG HOST
ARG PORT
ARG LOG_LEVEL
ARG DOMAINS_UPDATE_INTERVAL
ARG DB_FLUSH_BATCH_SIZE
ARG THREADS_COUNT
ARG QUEUE_SIZE
ARG RESOLVE_DOMAINS_BATCH_SIZE
ARG DB_EMPTY_ITER
ARG RESOLVE_EMPTY_ITER

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV NOTVISIBLE="in users profile"

ENV IS_PRODUCTION=$IS_PRODUCTION
ENV HOST=$HOST
ENV PORT=$PORT
ENV LOG_LEVEL=$LOG_LEVEL
ENV DOMAINS_UPDATE_INTERVAL=$DOMAINS_UPDATE_INTERVAL
ENV DB_FLUSH_BATCH_SIZE=$DB_FLUSH_BATCH_SIZE
ENV THREADS_COUNT=$THREADS_COUNT
ENV QUEUE_SIZE=$QUEUE_SIZE
ENV RESOLVE_DOMAINS_BATCH_SIZE=$RESOLVE_DOMAINS_BATCH_SIZE
ENV DB_EMPTY_ITER=$DB_EMPTY_ITER
ENV RESOLVE_EMPTY_ITER=$RESOLVE_EMPTY_ITER

RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential curl libpq-dev pkg-config openssh-server \
  net-tools htop \
  && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man \
  && apt-get clean

RUN mkdir /var/run/sshd
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
RUN sed -i "s/UsePrivilegeSeparation.*/UsePrivilegeSeparation no/g" /etc/ssh/sshd_config
RUN echo "export VISIBLE=now" >> /etc/profile
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

COPY set_root_pw.sh /set_root_pw.sh
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /set_root_pw.sh && chmod +x /docker-entrypoint.sh

WORKDIR /app

COPY *.py .
COPY requirements.txt .

RUN pip install --upgrade pip --no-cache
RUN pip install -r requirements.txt --no-cache

ENTRYPOINT ["/docker-entrypoint.sh"]
