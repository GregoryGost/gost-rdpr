FROM python:3.14.0-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV NOTVISIBLE="in users profile"

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  build-essential \
  curl \
  libpq-dev \
  pkg-config \
  openssh-server \
  net-tools \
  htop \
  pwgen \
  libpam-modules \
  libpam-modules-bin \
  && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man \
  && apt-get clean

RUN mkdir /var/run/sshd
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
RUN sed -i "s/UsePrivilegeSeparation.*/UsePrivilegeSeparation no/g" /etc/ssh/sshd_config
RUN echo "export VISIBLE=now" >> /etc/profile
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

WORKDIR /app

# see .dockerignore if you dont want to copy all
COPY . .

RUN pip install --upgrade pip --no-cache && pip install poetry --no-cache
RUN poetry install

COPY set_root_pw.sh /set_root_pw.sh
COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod +x /set_root_pw.sh && chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
