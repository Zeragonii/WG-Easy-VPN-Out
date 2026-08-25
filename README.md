# VPN Router

A small Flask-based management UI for policy-routing WG-Easy clients through
named outbound VPN sessions (OpenVPN or WireGuard).

## Current milestone: Foundation

This first build intentionally **does not alter routing**. It provides:

- Flask + Gunicorn web application
- Authentication
- Persistent SQLite database under `/data`
- Health/status endpoint
- Docker image with OpenVPN, WireGuard, nftables and iproute2 tooling installed
- Portainer/Docker Compose deployment
- GitHub Actions build and publish to GHCR

Routing/VPN management is added in later milestones after the deployment
foundation is verified.

## Local build

```bash
docker build -t vpn-router:dev .
docker compose up -d
```

Open:

`http://<docker-host>:8085`

Default credentials are supplied through environment variables in Compose.

## Persistent data

Everything persistent lives beneath `/data`.

Back this directory/volume up.

## Security

This container uses host networking and `NET_ADMIN` because later versions
will create VPN interfaces and policy-routing rules in the host network
namespace.

Do not expose the management UI directly to the Internet.


## v0.2.0 - WG-Easy discovery

Configure these environment variables:

```yaml
WG_EASY_URL: "http://127.0.0.1:51821"
WG_EASY_USERNAME: "your-wg-easy-username"
WG_EASY_PASSWORD: "your-wg-easy-password"
WG_EASY_VERIFY_TLS: "true"
APP_VERSION: "0.2.0"
```

WG-Easy API authentication uses the same username/password as its web UI.
The current WG-Easy API does not support Basic Auth when 2FA is enabled.

After deployment, open `/clients/` in VPN Router.

This milestone is read-only and does not alter routes, nftables, WireGuard,
OpenVPN, or WG-Easy configuration.
