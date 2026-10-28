#!/bin/sh
# Plants decoys for every agent listed in $AGENTS ("id:uid:gid ...").
# Runs as root with CHOWN/DAC_OVERRIDE/FOWNER only. Idempotent unless ROTATE=true.
set -eu
umask 022
mkdir -p /data/state/planted /data/guard /data/workspaces
for spec in $AGENTS; do
  id=${spec%%:*}; rest=${spec#*:}; uid=${rest%%:*}; gid=${rest#*:}
  marker="/data/state/planted/$id"
  if [ -f "$marker" ] && [ "${ROTATE:-false}" != "true" ]; then
    echo "skip $id (already planted; set planter.rotate=true to rotate)"
    continue
  fi
  mkdir -p "/data/workspaces/$id"
  agent-honeypot --state /data/state plant --config /config/honeypots.json \
    --target "/data/workspaces/$id" --agent-id "$id"
  chown -R "$uid:$gid" "/data/workspaces/$id"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$marker"
done
agent-honeypot --state /data/state export-guard-registry --out /data/guard/guard-registry.json
chmod 0644 /data/guard/guard-registry.json
chmod 0755 /data/guard
chown -R 10001:10001 /data/state
chmod 0700 /data/state
echo "planting complete"
