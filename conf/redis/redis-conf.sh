#!/bin/sh
set -e

cat <<EOF > /etc/redis.conf
bind 0.0.0.0
protected-mode yes
port 6379

# Redis 7 ACL FIX (THIS IS THE KEY)
user default on >${REDISPASS} allcommands allkeys

EOF

exec redis-server /etc/redis.conf
