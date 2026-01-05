#!/bin/sh
set -e

cat <<EOF > /etc/redis.conf
bind 0.0.0.0
protected-mode yes
port 6379
requirepass ${REDISPASS}
EOF

exec redis-server /etc/redis.conf
