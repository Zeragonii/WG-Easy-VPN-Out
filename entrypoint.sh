#!/bin/sh
set -eu

mkdir -p /data/openvpn /data/wireguard /data/backups

exec gunicorn \
    --bind "${VPN_ROUTER_BIND:-0.0.0.0}:${VPN_ROUTER_PORT:-8085}" \
    --workers "${GUNICORN_WORKERS:-2}" \
    --threads "${GUNICORN_THREADS:-2}" \
    --timeout 60 \
    --access-logfile - \
    --error-logfile - \
    "app:create_app()"
