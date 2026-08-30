FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       bind9-dnsutils \
       curl \
       iproute2 \
       iputils-ping \
       nftables \
       openvpn \
       sqlite3 \
       wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY VERSION /app/VERSION
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh \
    && mkdir -p /data/openvpn /data/wireguard /data/backups /data/geoip

VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
