#!/usr/bin/env sh

set -m

if [ ! -f /.root_pw_set ]; then
  /set_root_pw.sh
fi

if [[ -z "${APP_HOST}" ]]; then
  export APP_HOST="0.0.0.0"
if [[ -z "${APP_PORT}" ]]; then
  export APP_PORT="4000"
if [[ -z "${APP_WORKERS}" ]]; then
  # formula: (CPUS)*2+1
  # example for 1 CPU 1*2+1 = 3 | example for 2 CPU 2*2+1 = 5 | example for 20 CPU 20*2+1 = 41
  local CPUS=$(nproc)
  export APP_WORKERS=$($CPUS*2+1)

exec /usr/sbin/sshd -4 -D & cd /app && exec gunicorn main:app --bind=$APP_HOST:$APP_PORT --workers=$APP_WORKERS --worker-class=uvicorn.workers.UvicornWorker
