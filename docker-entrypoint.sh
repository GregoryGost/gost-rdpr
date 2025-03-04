#!/usr/bin/env sh

set -m

if [ ! -f /.root_pw_set ]; then
  /set_root_pw.sh
fi

exec /usr/sbin/sshd -4 -D & exec python /app/main.py
