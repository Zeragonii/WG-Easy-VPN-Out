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


## v0.2.1 - Handshake-derived client status

WG-Easy does not provide a persistent `online` boolean for clients.

VPN Router now derives a useful UI state from `latestHandshakeAt`:

- `< 3 minutes`: Online
- `< 10 minutes`: Recently active
- `>= 10 minutes`: Offline
- no handshake: Never connected

The clients page also displays human-readable RX/TX counters.


## v0.2.2 - Live WG-Easy client refresh

The WG-Easy Clients page now:

- polls VPN Router's read-only WG-Easy adapter every 5 seconds
- updates rows in place without a full-page reload
- updates handshake age locally every second
- shows the time of the latest successful API refresh
- keeps the last known client table visible if a refresh temporarily fails
- provides a manual "Refresh now" button

No routing or firewall changes are performed in this release.


## v0.3.1 - OpenVPN runtime management

Adds Connect/Disconnect, stable `tun-vpn<ID>` interface names, live tunnel
status, tunnel IPv4, uptime, exit-IP validation, and a runtime log tail.

OpenVPN is started with `--route-noexec` so provider configs cannot replace
the host's normal routing table. A narrowly scoped source rule is installed
only for the tunnel's own IP to support the exit-IP health probe.

WG-Easy client policy routing remains disabled in this release.

## v0.3.2 - Gateway-aware probe routing

Fixes exit-IP probing for OpenVPN providers that advertise a route gateway
with subnet topology, including PIA.

- parses `route-gateway` from OpenVPN `PUSH_REPLY`
- mirrors the tunnel's connected IPv4 route into the private probe table
- installs the probe default via the provider gateway when advertised
- falls back to `default dev <tun>` when no gateway is provided
- suppresses stale `sitnl_send` / `Network is unreachable` warnings while a
  tunnel is otherwise healthy
- keeps fatal authentication/TLS/startup errors visible

WG-Easy client policy routing is still disabled in this release.
