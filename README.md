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


## v0.3.3 - Auto-connect persistence

Adds persistent tunnel intent across container restarts.

- successful manual Connect enables Auto-connect
- manual Disconnect disables Auto-connect
- profile page has explicit Enable/Disable Auto-connect controls
- enabled OpenVPN profiles reconnect automatically at app startup
- failed startup attempts are logged without an aggressive retry loop

This makes VPN profiles survive Portainer/container restarts while keeping
failure behaviour predictable.


## v0.4.0 - Routing groups and security tidy-up

### Routing groups

Adds the first policy-routing engine:

- Routing Group CRUD UI
- each group receives a stable fwmark (`0x100 + group ID`)
- each group receives a dedicated route table (`10000 + group ID`)
- nftables table `inet vpn_router`
- one IPv4 source set per routing group
- nftables prerouting rules map source sets to fwmarks
- Linux `ip rule` entries map fwmarks to group route tables
- VPN-backed route tables use the active OpenVPN tunnel and provider gateway
- VPN groups can either block (kill-switch) or fall back to WAN when unavailable
- VPN-marked traffic is masqueraded on the selected VPN interface
- routing state rebuilds on application startup and Connect/Disconnect events

The nftables source sets remain intentionally empty in v0.4.0. WG-Easy client
assignment is planned for v0.5.0.

### CSRF protection

All state-changing web forms are protected with Flask-WTF CSRF tokens.

### VPN credential encryption

VPN passwords are encrypted at rest using Fernet with a key derived from
`SECRET_KEY`. Existing v0.3.x plaintext VPN passwords are migrated
automatically at startup.

**Important:** keep the same `SECRET_KEY` across upgrades/redeployments.
Changing it after credentials have been encrypted will make those stored
passwords undecryptable.


## v0.5.0 - WG-Easy client routing assignments

Adds the policy-routing UI that connects WG-Easy clients to Routing Groups.

- `Route via` dropdown on every discovered WG-Easy client
- assignments persist in SQLite by WG-Easy client ID
- assigned IPv4 addresses populate `inet vpn_router` source sets immediately
- assignments are restored automatically after container/app restart
- existing assignments survive clients going offline
- if WG-Easy later changes an assigned client's IPv4 address, VPN Router
  updates the stored address and nftables set membership automatically
- selecting `Unassigned / normal routing` removes the explicit policy
- routing groups with assigned clients cannot be deleted accidentally
- CSRF protection applies to assignment API changes via `X-CSRFToken`

Example:

    Laptop  192.168.3.2  → PIA Manchester
    Phone   192.168.3.3  → Default WAN
    Tablet  192.168.3.4  → PIA London

The routing path is:

    WG-Easy source IP
      → nftables routing-group set
      → fwmark
      → ip rule
      → dedicated routing table
      → WAN or selected VPN tunnel

## v0.5.1 - Clients page template hotfix

Fixes a Jinja template compilation error on the WG-Easy Clients page caused
by using Python list-comprehension syntax inside a Jinja expression.

Routing/assignment behaviour is unchanged from v0.5.0.


## v0.5.2 - Automatic routing reconciliation

Adds a lightweight routing-state reconciler. Every 3 seconds by default it
checks VPN-backed Routing Groups and rebuilds only when effective tunnel state
changes, including:

- connecting -> connected
- connected -> disconnected
- reconnect with a new tunnel IPv4
- reconnect with a different pushed `route-gateway`
- interface change
- fallback mode change

This fixes the case where a kill-switch group could receive `blackhole default`
while OpenVPN was still connecting and remain blocked until a manual rebuild.

Configure the interval with:

    ROUTING_RECONCILE_INTERVAL=3
