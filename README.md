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


## v0.6.0 - VPN retry and recovery

Adds automatic retry/recovery for enabled OpenVPN profiles.

Default exponential backoff is 5s, 10s, 20s, 40s, 80s, 160s, then capped at
300s. A successful connection resets the backoff immediately.

If an established VPN later dies, the resilience manager notices the
disconnected state and automatically enters the same retry process.

Routing Groups continue to obey their configured behaviour while a VPN is
unavailable:

- `Block` keeps the kill-switch active
- `WAN` continues to fail open through the normal WAN

Retry state is shown live on the VPN profile Runtime card.

Configuration:

    VPN_RETRY_CHECK_INTERVAL=2
    VPN_RETRY_BASE_SECONDS=5
    VPN_RETRY_MAX_SECONDS=300
    VPN_RETRY_MAX_FAILURES=0

`VPN_RETRY_MAX_FAILURES=0` means retry indefinitely at the maximum backoff.
Set a positive value to stop after that many failures.

Retry state persists at `/data/runtime/retry-state.json`.


## v0.6.1 - Dashboard refresh

Replaces the stale early-development dashboard copy with a live operational
overview.

Dashboard now shows:

- current application version
- routing reconciler / VPN resilience status
- WG-Easy visibility
- assigned WG-Easy client count
- outbound VPN profile count
- auto-connect enabled profile count
- connected / connecting tunnel counts
- routing group count
- policy-routing / kill-switch capabilities
- configured reconcile and retry timings
- networking tool availability
- current feature-set summary and next milestone


## v0.6.2 - WG-Easy dashboard client totals

Adds a live `Total clients` metric to the WG-Easy dashboard card.

- `Total clients` = number currently returned by WG-Easy `/api/client`
- `Assigned clients` = number with a saved VPN Router routing-group assignment

If the WG-Easy API is temporarily unavailable, the dashboard shows the total
as unavailable while retaining the persisted assigned-client count.


## v0.7.0 - Observability and dashboard polish

Expands the dashboard into a live operational overview.

WG-Easy summary:
- total discovered clients
- online-now count
- recently-active count
- persistent assigned-client count

Outbound VPN health table:
- profile/provider
- connected/connecting/failed state
- tunnel interface and IPv4
- pushed route gateway
- observed public exit IP
- tunnel uptime
- auto-connect state

Routing group health table:
- assigned-client count per group
- configured exit
- effective exit
- fallback/kill-switch policy
- live ready/fallback/blocked state
- fwmark and routing table ID

The release is intentionally observability-only: it does not change packet
marking, route construction, VPN startup, retry, or reconciliation behaviour.


## v0.7.1 - Local-network routing bypass

Fixes policy-routed WG-Easy clients losing access to local services such as
Portainer, UniFi, or Docker-hosted applications.

Routing-group marks now apply only after local/private IPv4 destinations are
excluded from the nftables prerouting chain.

Bypassed destinations:

- `127.0.0.0/8`
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `169.254.0.0/16`

Result:

- LAN/private traffic uses normal local routing
- internet-bound traffic still uses the selected routing group
- kill-switch / WAN fallback behaviour still applies to internet traffic
- Docker bridge/private-network destinations are no longer accidentally sent
  toward outbound VPN routing tables


## v0.7.2 - Image-owned application version

The application version is now stored in the repository's root `VERSION` file
and baked into the GHCR image at build time.

Normal deployments no longer need an `APP_VERSION` environment variable in
Portainer. When `ghcr.io/...:latest` is pulled and redeployed, the dashboard
automatically reports the version contained in that image.

Version resolution order:

1. optional `APP_VERSION` environment override, useful for development
2. `/app/VERSION` baked into the container image
3. `unknown` if neither is available

For each release, update the repository `VERSION` file before building/pushing.


## v0.7.3 - Async observability and update awareness

Removes external network probes from the normal dashboard request path.

### Faster dashboard loading

The dashboard no longer performs `api.ipify.org` exit-IP probes while the page
is rendering. A background observability service probes connected outbound VPNs
every 60 seconds by default and caches the last successful public exit IP.

The browser polls a lightweight local JSON endpoint every 10 seconds to update:

- tunnel state
- tunnel IPv4
- pushed gateway
- uptime
- cached public exit IP

A transient exit-IP probe failure no longer erases the last successful result;
the dashboard keeps the known address and marks the refresh as failed.

### Update awareness

The same background service checks the repository's public `VERSION` file every
6 hours by default:

    https://raw.githubusercontent.com/Zeragonii/WG-Easy-VPN-Out/main/VERSION

When the repository version is newer than the installed image version, the
dashboard shows an `Update available` banner with the installed/latest versions
and a repository link.

No Docker socket, Portainer credentials, GitHub token, or self-update privilege
is required.

Configuration:

    EXIT_IP_PROBE_INTERVAL=60
    UPDATE_CHECK_INTERVAL=21600
    UPDATE_VERSION_URL=https://raw.githubusercontent.com/Zeragonii/WG-Easy-VPN-Out/main/VERSION
    UPDATE_REPOSITORY_URL=https://github.com/Zeragonii/WG-Easy-VPN-Out


## v0.7.4 - Dashboard-triggered update checks

GitHub update awareness is now demand-driven instead of timer-driven.

When the dashboard opens, its asynchronous live-status request asks the server
for update state. The server checks the repository `VERSION` file only when its
cached result is stale, so the dashboard remains fast while still getting a
fresh-enough answer whenever it is actually viewed.

Configuration:

    UPDATE_CHECK_CACHE_SECONDS=900

Default: 900 seconds (15 minutes).

Examples:

- `60` = at most one GitHub check per minute
- `900` = at most one check every 15 minutes
- `3600` = at most one check per hour
- `0` = check GitHub on every dashboard live-status request

The exit-IP background polling behaviour is unchanged.


## v0.7.5 - Flexible version comparison

Update awareness now supports arbitrary numeric depth and alphabetic suffixes.

Examples that compare correctly:

- `0.7.5` < `0.7.5.1`
- `0.7.5` < `0.7.5a`
- `0.7.5a` < `0.7.5b`
- `0.7.5.3` < `0.7.5.3a`
- `0.7.5.9` < `0.7.5.10`
- optional leading `v` is accepted

The project's convention intentionally treats an added suffix as a later
micro-patch, so `0.7.5a` is considered newer than `0.7.5`.


## v0.8.0 - Backup and Restore

Adds authenticated backup and restore under **Backup & Restore**.

Backups are structured ZIP archives containing:

- `manifest.json`
- `data.json`
- VPN configuration files under `configs/openvpn/` and `configs/wireguard/`
- optionally `secret-key.txt`

Persistent data includes VPN profiles, encrypted credentials, routing groups,
fallback settings, policy allocations and WG-Easy client assignments.

Runtime logs, PID/auth files, retry state, live tunnel state and transient route
probe data are intentionally excluded.

### SECRET_KEY choice

By default the application secret is not included. The UI allows the operator
to reveal/copy the current key for separate secure storage.

An operator can instead explicitly include `SECRET_KEY` in the archive after
acknowledging that compromise of such a backup may expose encrypted VPN
credentials and application session integrity.

If a restored archive includes a different key, the application does not try
to mutate Portainer/container environment variables. It restores the data and
prominently instructs the operator to set the included key as `SECRET_KEY` and
redeploy before encrypted VPN credentials can be used.

Restore validates archive structure, paths, entity references and required
configuration files before replacing current persistent configuration.
