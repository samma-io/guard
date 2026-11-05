#!/usr/bin/env bash
# Block one IP for a while, the way the detection platform would.
#
#   ./examples/block.sh 203.0.113.44 2h "credential stuffing" detection/auth-anomaly
#
# Needs the nats CLI and NATS_URL / NATS_CREDS for a user with write access.
set -euo pipefail

ip=${1:?ip}
ttl=${2:-1h}
reason=${3:-manual block}
source=${4:-manual}

case $ttl in
  *h) secs=$(( ${ttl%h} * 3600 )) ;;
  *m) secs=$(( ${ttl%m} * 60 )) ;;
  *s) secs=${ttl%s} ;;
  *) echo "ttl like 30m, 2h or 90s" >&2; exit 1 ;;
esac

id=$(printf '%s' "$ip" | sha256sum | cut -c1-12)
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
exp=$(date -u -d "+${secs} seconds" +%Y-%m-%dT%H:%M:%SZ)

nats kv put samma-guard-rules "ip.$id" "$(cat <<EOF
{"id":"$id","kind":"ip","match":"$ip","action":"block","reason":"$reason","source":"$source","created":"$now","expires":"$exp"}
EOF
)"
echo "blocked $ip until $exp (key ip.$id)"
echo "unblock: nats kv del -f samma-guard-rules ip.$id"
