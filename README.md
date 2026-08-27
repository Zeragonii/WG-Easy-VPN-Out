# VPN Router

## AI-assisted development

This project was created with substantial assistance from **OpenAI's ChatGPT**.

AI assistance was used during the design and implementation process for tasks
including architecture discussion, code generation and refactoring, debugging,
release planning, documentation, test design, and analysis of diagnostic output.

The project was not developed autonomously by an AI system. Its requirements,
deployment environment, testing decisions, validation, and release approval
were directed and performed by the project maintainer. Changes were repeatedly
tested against a real WG-Easy/OpenVPN deployment before the 1.0 release.

This disclosure is included intentionally so users and contributors can make an
informed judgement about the project's development process and provenance.

A small Flask-based management UI for policy-routing WG-Easy clients through
named outbound VPN sessions (OpenVPN or WireGuard).

## What VPN Router does

VPN Router is a LAN-hosted policy-routing controller designed to sit alongside
WG-Easy. It lets individual WG-Easy clients use different outbound paths
without changing the WireGuard configuration distributed to those clients.

Current functionality includes:

- WG-Easy client discovery and metadata synchronisation.
- Per-client assignment to routing groups.
- Temporary per-client routing overrides with automatic expiry/revert.
- Default-WAN or OpenVPN-backed routing groups.
- Private/local IPv4 destination bypass.
- Per-group **Block / kill-switch** or **WAN fallback** behavior.
- Per-group DNS policy:
  - **Existing / client DNS**
  - **PIA DNS**
  - **Custom DNS**
- Transparent forced classic DNS interception for UDP/TCP port 53.
- Routing-group-aware DNS visibility/leak testing.
- VPN exit-IP visibility.
- Routing health and recent transition history.
- Live WG-Easy traffic visibility with per-client and per-route RX/TX rates.
- OpenVPN retry/recovery with exponential backoff and connect timeout.
- VPN connection policies:
  - **Always connected**
  - **On demand**
- Assignment-driven On-demand lifecycle:
  - an assignment means the outbound VPN is required
  - the target VPN connects before a client assignment is moved
  - unused On-demand tunnels disconnect after an idle grace period
- Provider/profile intelligence.
- Provider adapter framework with PIA-specific interpretation and generic
  fallback for unknown providers.
- Encrypted VPN credentials.
- First-run setup wizard and persistent settings.
- Backup/restore.
- Diagnostics and release-preflight checks.
- GitHub update awareness.

### Current runtime scope

OpenVPN is the supported outbound VPN runtime today.

WireGuard configuration parsing/intelligence exists, but outbound WireGuard
runtime activation is not yet implemented.

VPN Router does not replace WG-Easy. WG-Easy remains the WireGuard server and
client-management layer; VPN Router adds outbound policy routing around it.

## Basic startup guide

### 1. Requirements

You need:

- Docker / Docker Compose or Portainer
- WG-Easy already running
- host networking
- `/dev/net/tun`
- `NET_ADMIN`
- `NET_RAW`
- IPv4 forwarding enabled on the host
- a LAN gateway route for the WG-Easy client subnet back to the VPN Router host

VPN Router uses host networking because it manages host routes, policy rules,
nftables and VPN tunnel interfaces directly.

### 2. Minimal Compose example

```yaml
services:
  vpn-router:
    image: ghcr.io/zeragonii/wg-easy-vpn-out:latest
    container_name: vpn-router
    network_mode: host
    restart: unless-stopped

    cap_add:
      - NET_ADMIN
      - NET_RAW

    devices:
      - /dev/net/tun:/dev/net/tun

    environment:
      TZ: Europe/London
      VPN_ROUTER_PORT: "8085"
      VPN_ROUTER_BIND: "0.0.0.0"
      SECRET_KEY: "replace-with-a-long-stable-random-secret"

    volumes:
      - vpn-router-data:/data

volumes:
  vpn-router-data:
```

Keep `SECRET_KEY` stable. It protects encrypted stored values; changing it later
can make previously encrypted data unreadable.

### 3. Host networking prerequisites

Enable IPv4 forwarding:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Persist it using your distribution's normal sysctl configuration.

Your LAN gateway must also know how to return traffic to the WG-Easy client
subnet. For example:

```text
WG-Easy clients: 192.168.3.0/24
VPN Router host: 192.168.1.202
```

requires a route equivalent to:

```text
192.168.3.0/24 via 192.168.1.202
```

### 4. First start

Start the container and open:

```text
http://<VPN-Router-host>:8085
```

A fresh install creates a one-time setup token at:

```text
/data/runtime/setup-token
```

The token is also written to the container logs.

Use the setup wizard to:

1. Create the administrator account.
2. Configure WG-Easy URL and credentials.
3. Test the WG-Easy connection.
4. Finish setup.

### 5. Add outbound VPN profiles

Import OpenVPN configurations from the VPN Profiles page.

Each profile can have:

- friendly name
- provider
- credentials where required
- Allow automatic connection
- **Always connected** or **On demand** connection policy

For On-demand profiles, **Allow automatic connection must be enabled**. Allow automatic connection means VPN
Router is permitted to start the profile automatically; On demand determines
when it should run.

### 6. Create routing groups

Create a routing group and select:

- outbound VPN profile or Default WAN
- fallback behavior
- DNS policy

VPN-backed groups receive their own fwmark and policy-routing table.

### 7. Assign WG-Easy clients

Assign WG-Easy clients to routing groups from the Clients page.

For an On-demand profile:

```text
client assigned
→ VPN required
→ tunnel starts if needed
→ VPN becomes ready
→ assignment/routing takes effect
```

When the final assignment using that VPN is removed, it enters the idle grace
period and then disconnects.

This is assignment-driven rather than handshake-driven, so the outbound tunnel
can already be ready when an offline WireGuard client reconnects.

## Routing and DNS behavior

### Local/private traffic bypass

The following ranges bypass the outbound VPN path by default:

```text
127.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16
```

Forced DNS is handled specially so provider DNS inside a private range can
still be routed into the VPN.

### Forced classic DNS

Forced PIA/custom DNS intercepts classic:

```text
UDP/53
TCP/53
```

and transparently redirects it to the configured resolver.

DNS-over-HTTPS is not intercepted. DNS-over-TLS is not transparently rewritten,
although it still follows the routing group's normal outbound path.

### Kill-switch behavior

With **Block / kill-switch**, a VPN-backed group is blackholed if its VPN is
unavailable.

With **WAN fallback**, traffic may use WAN while the VPN is unavailable.

## Data and backups

Persistent state lives under:

```text
/data
```

This includes the SQLite database, imported VPN configs, encrypted credentials,
runtime metadata and setup state.

Use a persistent volume or bind mount for `/data`.

Built-in backup/restore can export the application configuration and may
optionally include the `SECRET_KEY`. Treat backups containing the key as
sensitive.

## Security notes

VPN Router is intended as a trusted LAN administration service.

It requires elevated networking capabilities because it manages interfaces,
routes, policy rules and nftables. It intentionally does **not** require the
Docker socket or a fully privileged container.

Recommended practice:

- keep the UI LAN-only
- use a strong stable `SECRET_KEY`
- restrict host access
- back up `/data`
- do not expose the admin UI directly to the public internet

## Release and patch history

The sections below are intentionally retained as the project's development
record. They document the incremental features, fixes, regressions and
hardening work that led to the current release.

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

## v0.3.3 - Allow automatic connection persistence

Adds persistent tunnel intent across container restarts.

- successful manual Connect enables Allow automatic connection
- manual Disconnect disables Allow automatic connection
- profile page has explicit Enable/Disable Allow automatic connection controls
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

## v0.9.0 - Core hardening and diagnostics

The 0.9 line begins the pre-1.0 hardening phase.

### Routing lifecycle cleanup

Policy routing reconciliation now identifies stale rules/tables created by
deleted routing groups using the application's exact allocation relationship:

- priority/table = `10000 + group_id`
- fwmark = `0x100 + group_id`

A group deletion explicitly removes its allocated rule/table before deleting
the database row, and every full rebuild performs a second stale-state sweep.
Unrelated host policy rules are not deliberately matched by this cleanup.

### OpenVPN connecting timeout

An enabled OpenVPN profile can no longer remain in `connecting` forever merely
because the OpenVPN process is alive. If it has not acquired a tunnel IPv4
address within the configured timeout, the resilience manager stops that
attempt and enters the existing exponential retry path.

Configuration:

    VPN_CONNECT_TIMEOUT_SECONDS=45

Set to `0` to disable the timeout.

### Diagnostics

A new authenticated **Diagnostics** page provides read-only troubleshooting
state and a downloadable text report containing:

- application version and non-secret runtime settings
- VPN tunnel state, interfaces, tunnel IPs and pushed gateways
- routing-group state and policy allocations
- IPv4 policy rules
- application-managed route tables
- nftables `inet vpn_router` state
- `wg0` link state and host default route

The report intentionally excludes `SECRET_KEY`, admin credentials, WG-Easy
credentials, VPN usernames/passwords, and VPN configuration file contents.

### Internal API cleanup

Cross-service users now call public VPN runtime helpers for log-tail/gateway
inspection rather than depending directly on private helper methods.

## v0.9.1 - Service lifecycle and recovery hardening

### Graceful background-service shutdown

Routing reconciliation, VPN resilience and observability managers now expose
bounded `stop()` operations that signal and join their worker threads. The app
tracks them centrally and registers process-exit cleanup in reverse startup
order. A stuck background thread cannot delay shutdown indefinitely.

Managers also clear their stop event when restarted, making their lifecycle
safe for development/test application recreation.

### Restore reconciliation

After a configuration restore:

- retry state for removed VPN profile IDs is pruned immediately
- restored profiles receive clean retry state
- the routing reconciler is explicitly invalidated so the next tick performs
  a fresh comparison/rebuild
- stale exit-IP cache entries are removed immediately

This reduces the small post-restore window where background managers could
still contain state from the replaced configuration.

### Diagnostics expansion

Diagnostics now reports whether each background manager is running and includes
VPN retry/recovery state such as failure count, next retry delay and last
successful recovery timestamp.

### Runtime API cleanup

The observability service now uses a public `VPNRuntimeService.exit_ip()` API
instead of directly calling the private `_exit_ip()` helper.

## v0.9.2 - Migration and restore hardening

### Versioned database migrations

VPN Router now has an ordered schema-migration framework and a persistent
`schema_migrations` table.

Schema v1 is the baseline schema used through v0.9.1. Existing installations
are validated and recorded as v1; fresh installs are bootstrapped from the
SQLAlchemy metadata and then recorded through the same migration path.

Future schema changes should be implemented as ordered migrations instead of
relying on `db.create_all()` to evolve existing databases.

Startup refuses a database whose recorded schema is newer than the running
application supports.

Diagnostics and new backups report the current schema version/history.

### Restore validation

Restore inspection now happens completely before live tunnels or persistent
state are touched and validates:

- backup application/format/schema compatibility
- duplicate ZIP member names
- path traversal and unexpected archive files
- archive member count and total uncompressed size
- UTF-8 VPN configuration files and safe filenames
- required fields, types and length limits
- duplicate profile/group/assignment IDs and names
- duplicate WG-Easy external IDs and assigned IPv4 addresses
- valid IPv4 client addresses
- VPN profile and routing-group references
- routing-group fwmark/table allocations against the expected deterministic IDs
- unreferenced or missing VPN configuration files

Backups created by a newer unsupported database schema are rejected with an
explicit instruction to upgrade the application before restoring.

### Staged restore writes

VPN configuration files are now written and verified in a temporary staging
directory before the live configuration is replaced. If the database/file
replacement fails, the SQL transaction is rolled back and the previous config
files are restored.

## v0.9.3 - Release Candidate Readiness

v0.9.3 is intentionally feature-frozen. Its purpose is to verify that the
existing OpenVPN/WG-Easy policy-routing feature set is ready to be called 1.0.

Diagnostics now includes a **Release readiness** preflight. It performs
read-only checks against the live instance and reports Pass / Warning / Fail for:

- database schema compatibility
- persistent `/data` writability
- required networking tools
- background service health
- VPN configuration-file presence
- deterministic routing mark/table allocations
- live IPv4 policy rules
- nftables `inet vpn_router`
- enabled OpenVPN tunnel health
- client-assignment integrity
- basic SECRET_KEY hygiene

Warnings do not block readiness; failed checks do.

See `RELEASE_CHECKLIST.md` for the manual tests to perform before tagging
`v1.0.0`, and `CHANGELOG.md` for the consolidated project history.

## v0.9.3a - Preflight UI hotfix

Fixes the Diagnostics **Run preflight** button. The preflight JavaScript is now rendered after the Diagnostics content rather than inside the document title/head block, so the DOM elements exist before event listeners are attached.

## v0.9.3b - Resilience accounting hotfix

A retry process successfully starting is no longer counted as a successful VPN connection. Retry failures and exponential backoff remain intact until the tunnel is actually observed as connected.

## v1.0.0 - Stable OpenVPN Release

v1.0.0 marks the first stable release of WG-Easy-VPN-Out.

The 1.0 feature set includes:

- WG-Easy client discovery and live status
- outbound OpenVPN profile management
- persistent auto-connect and retry/recovery
- per-client routing-group assignment
- nftables-based policy routing
- deterministic fwmark/routing-table allocation
- VPN kill-switch and optional WAN fallback
- local/RFC1918 destination bypass
- live routing reconciliation
- asynchronous exit-IP observability
- GitHub update awareness
- portable backup/restore with optional SECRET_KEY inclusion
- versioned database schema migrations
- restore validation and rollback hardening
- diagnostics export and release-readiness preflight

The 1.0 release was validated through:

- a fresh installation
- restore of an existing production backup
- successful recovery of restored VPN profiles and routing assignments
- deliberate OpenVPN connection failure and timeout/retry testing
- stale routing-rule/table deletion testing
- kill-switch behavior verification
- a clean 11/11 release-readiness preflight

Outbound WireGuard support remains intentionally deferred to a post-1.0 release.

## v1.1.0 - First-run setup and application settings

Fresh deployments now require only the deployment-level environment values
needed before the web application can start:

- `SECRET_KEY`
- `VPN_ROUTER_BIND`
- `VPN_ROUTER_PORT`
- `VPN_ROUTER_DATA_DIR` (optional)
- `TZ`

On a new empty `/data` volume, VPN Router generates a one-time setup token and
prints it to the container logs. The browser setup wizard uses that token to
create the administrator account and validate/store the WG-Easy connection.

Application settings now live in the database and are editable from
**Settings**. WG-Easy credentials are encrypted using the existing
`SECRET_KEY`-derived Fernet mechanism.

Legacy v1.0 environment variables remain backward compatible: on upgrade they
are imported only when the corresponding database setting does not already
exist. Once imported, the database/UI value becomes authoritative, so users can
remove the old Compose variables at their convenience.

Settings cover WG-Easy, routing reconciliation, VPN resilience, observability,
update awareness, and administrator account management. Runtime background
services reload applicable settings after a save.

Backups created by v1.1 include application settings. Older backups without
settings remain accepted.

## v1.2.0 - Routing health and DNS leak visibility

v1.2.0 adds operational visibility without changing DNS behavior.

### Routing-group health

Routing groups now show the configured exit, effective exit, live route state,
DNS visibility, and recent persisted state transitions. Transitions such as
VPN → blocked → VPN or VPN → WAN fallback are recorded automatically when the
routing reconciler observes a material state change.

### DNS leak visibility

VPN-backed routing groups can run a DNS leak visibility probe. The probe is
generated by VPN Router itself and pinned to the selected outbound tunnel. It
uses the public bash.ws DNS-leak service to observe resolver networks and
compares resolver ASN information with the VPN exit ASN.

The UI intentionally uses conservative language:

- **No obvious leak** — observed resolver ASN matches the VPN exit ASN.
- **Potential DNS leak** — one or more resolver ASNs differ.
- **Resolver observed / unavailable** — there is not enough data for a strong
  comparison.

A different resolver ASN is not automatically proof of a leak: legitimate
third-party DNS providers can differ from the VPN provider. The feature is
observational only and does not rewrite or enforce DNS. It also does not claim
that every individual WG-Easy client necessarily uses the exact same resolver
path as VPN Router's pinned probe.

Automatic probes default to every 900 seconds and can be disabled by setting
the interval to 0 in Settings; a manual test remains available from the Routing
Group Health page.

## v1.2.1 - DNS probe routing fix

v1.2.0 bound `dig` directly to the VPN tunnel address. On hosts whose configured
DNS resolver is reachable through the normal LAN/default route, that can create
an unusable source/destination path and cause the DNS probe to time out.

v1.2.1 switches the DNS trigger stage to `ping -I <VPN interface>`, matching the
upstream bash.ws Linux test model more closely: hostname resolution is left to
the container's configured resolver, while the generated request and result
retrieval remain associated with the selected VPN path.

`dig` is no longer required. `ping` is included in the container image and
networking-tools preflight.

## v1.2.2 - DNS trigger result handling fix

The bash.ws DNS leak test uses generated hostnames only to cause the system
resolver to perform lookups. The subsequent ICMP ping does not need to succeed,
and the upstream shell implementation intentionally discards the ping result.

v1.2.1 incorrectly treated failed hostname/ping results as evidence that no DNS
queries had been generated. v1.2.2 now mirrors the upstream behavior: it fires
the tunnel-bound ping triggers without interpreting their return codes, then
uses the bash.ws result endpoint itself to determine whether resolvers were
observed.

## v1.3.0 - DNS policy and leak prevention

Routing groups can now control classic DNS for assigned WG-Easy clients.

### DNS modes

- **Existing / client DNS** — preserves v1.2 behavior.
- **Force PIA DNS** — transparently redirects UDP/TCP port 53 to
  `10.0.0.242` and routes it through the group's PIA tunnel.
- **Force custom DNS** — transparently redirects UDP/TCP port 53 to a
  user-supplied IPv4 resolver through the group's VPN routing table.

Forced DNS is implemented inside VPN Router's nftables policy table. DNS
traffic is marked before RFC1918/private-address bypass rules, which allows PIA
DNS (`10.0.0.242`) to use the VPN path even though the rest of `10.0.0.0/8`
continues to retain normal local/private-network bypass behavior.

DNS follows kill-switch behavior. A block-on-failure VPN group retains its
blackhole policy when the tunnel is unavailable; VPN Router does not silently
fall back to the host resolver. WAN-fallback groups stop forcing provider DNS
while WAN fallback is active.

The Routing Group Health page now shows the configured DNS policy and resolver.
Manual DNS visibility tests for forced-DNS groups query the selected resolver
through the actual VPN tunnel before retrieving external resolver observations.

v1.3.0 controls classic UDP/TCP port 53 only. DNS-over-HTTPS is intentionally
out of scope and is not intercepted.

## v1.4.0 - Provider metadata and profile intelligence

VPN Router now derives read-only metadata from imported VPN configurations.

For OpenVPN profiles it surfaces the primary remote endpoint and port,
protocol/transport, device, authentication style, TLS mode, cipher declaration,
remote count, conservative provider detection, and conservative region hints
where endpoint naming clearly exposes one.

WireGuard configuration files receive equivalent endpoint/provider/transport
metadata where available, although outbound WireGuard runtime activation
remains deferred.

Metadata is parsed on demand from the config rather than duplicated in the
database. Existing profiles benefit immediately and no schema migration is
required. A user-entered Provider always takes precedence over heuristic
detection.

Provider intelligence is informational only. v1.4.0 does not rewrite configs,
select endpoints, or add provider-specific routing automation.

## v1.4.1 - Region hint parsing fixes

The profile-intelligence parser now handles PIA country-only endpoint names,
including `ireland.privacy.network`, and understands PIA's `-so` suffix as a
Streaming Optimized endpoint variant.

## v1.4.2 - Provider adapter framework

The v1.4 profile-intelligence feature now separates generic VPN parsing from
provider-specific interpretation.

- Generic OpenVPN/WireGuard parsers extract protocol-level facts.
- Provider adapters interpret provider-specific naming and capabilities.
- Unknown providers use a generic fallback without breaking metadata display.
- PIA-specific region parsing now lives entirely in the PIA adapter.
- Detection confidence and reason are shown on the profile detail page.
- The PIA adapter exposes DNS presets for future reuse, without changing current
  DNS routing behavior.

No database migration or routing/runtime behavior change is included.

## v1.5.0 - On-demand VPN connections

VPN profiles now support **Always connected** and **On demand** connection
policies.

On-demand requirement is assignment-driven: if any WG-Easy client is assigned
to any routing group targeting a profile, that VPN is required even if the
WireGuard client is currently offline. This keeps the outbound tunnel ready
before the WG-Easy client connects.

Assignment changes use connect-before-switch behavior for on-demand targets:
VPN Router starts the new outbound VPN and waits for a confirmed tunnel before
persisting the client's new routing-group assignment. If the new VPN cannot
connect, the assignment is left unchanged.

Once a profile has no consumers it enters a 60-second idle grace period before
disconnecting. Multiple clients naturally reference-count a shared profile, so
it remains connected until its final assignment moves away.

Existing profiles migrate to **Always connected**, preserving current behavior
until the user explicitly opts a profile into On demand.

## v1.5.1 - Standby state and DNS probe routing fixes

Unused enabled on-demand profiles now display **Standby** rather than inheriting
a historical OpenVPN error from their log and appearing as Failed. Runtime API
and diagnostics use the same distinction; genuine failures while a profile is
required continue to report as Failed.

The forced-DNS manual validator now mirrors the routing-group policy table for
its locally generated resolver query. WG-Easy client traffic is policy-routed
from nftables prerouting, but local container probes do not traverse that hook.
v1.5.1 temporarily installs a narrow source+destination rule for the selected
resolver and removes it after the probe, making the validation path match the
routing group's actual VPN egress without changing client routing behavior.

## v1.5.2

### Documentation transparency

- Moved the existing **AI-assisted development** disclosure to the top of
  `README.md`, immediately after the project title.
- Preserved the disclosure text unchanged.
- Future appended release notes can remain below it without moving the
  disclosure again.
- No application, routing, runtime, schema, or container behavior changes.

## v1.5.3

### VPN profile route hotfix

- Fixed `/vpn-profiles/` returning HTTP 500 because detail-page template
  variables were accidentally passed from the list route.
- Restored `runtime_display_state` and `on_demand` to the VPN profile detail
  template context where they belong.
- Added release-validation checks to catch this route/template context
  regression in future builds.
- Retains the v1.5.1 standby/DNS-probe fixes and the v1.5.2 README disclosure
  placement.
- No schema, routing-policy, or on-demand lifecycle behavior changes.

## v1.5.4

### VPN client list status semantics

- Unused enabled on-demand VPN profiles now display **Offline** in the VPN
  Clients list instead of inheriting historical OpenVPN failure state.
- **Failed** is reserved for profiles that are actually required/expected to
  be connected and have genuinely failed.
- Individual profile detail pages retain the richer **Standby** state and real
  failure diagnostics.
- No schema, routing, DNS, lifecycle, or provider-adapter behavior changes.

## v1.5.5

### DNS probe hotfix

- Fixed the forced-DNS manual probe raising `name 'resolver_ip' is not defined`.
- Rebuilt the explicit resolver probe so `resolver_ip` and routing-table scope
  are explicit and correctly scoped.
- Preserved the narrow source+destination policy rule used to mirror the
  routing group's VPN path for locally generated DNS tests.
- Added better command stderr/stdout detail when a temporary rule or DNS query
  genuinely fails.
- Retains the v1.5.4 VPN-list Offline/Failed status semantics.
- No schema, client routing, DNS interception, or on-demand lifecycle behavior
  changes.

## v1.5.6

### DNS probe regression fix

- Restored the generic DNS leak probe to a resolver-agnostic implementation.
- Removed accidental `resolver_ip` / `routing_table_id` references from
  `run_dns_leak_probe()`.
- Existing/client DNS leak tests once again use the original tunnel-bound
  bash.ws lookup flow.
- Forced/custom DNS validation remains isolated in
  `run_explicit_resolver_probe()`.

### Manual disconnect status fix

- A manually disabled/disconnected VPN profile now reports **Disconnected**
  rather than inheriting historical OpenVPN log errors as **Failed**.
- Historical errors are suppressed while a profile is disabled.
- Enabled profiles that genuinely fail still report **Failed**.
- On-demand Standby/Offline behavior remains unchanged.

- No schema, routing-policy, DNS interception, provider-adapter, or on-demand
  lifecycle changes.

## v1.5.7

### Forced-DNS probe path fix

- Changed forced/custom DNS validation to use the routing group's actual
  fwmark, matching WG-Easy client policy routing.
- Local DNS probe traffic is temporarily marked in an nftables route/output
  chain because local traffic does not traverse prerouting.
- Existing fwmark policy rules and postrouting masquerade are reused by the
  probe.
- Removed the previous source+destination policy-rule approximation.
- Temporary nftables probe chains are cleaned up after each test.
- Existing/client DNS probing is unchanged.
- No schema, client DNS interception, routing-group policy, or on-demand
  lifecycle changes.

## v1.5.8

### Routing-group DNS observability cleanup

- DNS visibility for Routing Group Health is now cached per routing group
  instead of per VPN profile.
- Automatic/background DNS checks now honor each routing group's configured DNS
  policy.
- Groups using PIA/custom forced DNS automatically run the same explicit
  resolver test used by the **Run DNS leak test now** button.
- Groups using Existing/client DNS continue to use the generic tunnel-bound
  DNS visibility probe.
- Manual and automatic checks now write to the same routing-group cache, so a
  startup generic result can no longer overwrite a forced-DNS result.
- Multiple routing groups may share one VPN profile while retaining independent
  DNS-policy visibility.
- Profile-level generic DNS cache remains available for profile observability.
- No schema, routing, DNS interception, provider-adapter, or on-demand lifecycle
  changes.

## v1.5.10

### Dashboard VPN-status semantics

- Dashboard status handling now matches the current On-demand lifecycle.
- Intentional idle On-demand profiles show **Offline** rather than Failed.
- Dashboard fault counts only include profiles expected to be connected and
  genuinely unhealthy.
- No runtime/routing behavior changes.

## v1.5.11

### Dashboard 500 hotfix

- Removed an invalid dashboard call to `VPNResilienceManager.state()`.
- Restored dashboard and live-dashboard API rendering.
- Keeps the v1.5.10 Offline/Failed status semantics unchanged.

## v1.5.12

### Final v1.5 hardening

- Prevented new client assignments to routing groups backed by a VPN profile
  that does not allow automatic connection.
- Clarified Auto-connect wording as **Allow automatic connection**.
- Manual disconnect now warns when an On-demand VPN is still required and makes
  clear that the affected routing groups will remain blocked until automatic
  connection is allowed again.
- Added assignment counts to VPN profile views.
- No routing, DNS or lifecycle behavior changes.

## v1.6.0

### Temporary routing overrides

- Added a separate persisted override layer above permanent WG-Easy client
  assignments.
- Overrides support 15m, 30m, 1h, 4h and Until cancelled durations.
- Expiry automatically restores the permanent assignment or normal routing.
- VPN targets connect successfully before an override becomes effective.
- On-demand lifecycle and nftables routing follow the effective overridden
  assignment.
- Added override start/cancel/expiry history and Clients UI controls.
- Schema upgraded to v6.

## v1.6.1

### Temporary override UI cleanup

- Moved temporary override editing into an in-page modal behind a compact
  **Override** button.
- Modal shows permanent/effective route, current override, live countdown and
  apply/replace/cancel actions.
- No schema or routing behavior changes.

## v1.6.2

### WG-Easy Clients UI hotfix

- Restored the missing `renderEffectiveRoute()` client-side helper.
- Fixed the WG-Easy Clients page error introduced by the v1.6.1 UI cleanup.
- No schema or routing behavior changes.

## v1.6.3

### Override modal polling hotfix

- Polling refreshes no longer reset unsaved Override Route/Duration selections
  in an open modal.
- Live backend state still refreshes normally while the form selection remains
  intact.
- No schema or routing behavior changes.

## v1.6.4

### Final temporary-override UI hardening

- Unavailable VPN-backed override targets are disabled in the modal.
- Override history now distinguishes Started, Replaced, Cancelled and Expired.
- History timestamps use friendly relative-time display.
- No schema or routing behavior changes.

## v1.7.0

### Deeper observability and traffic visibility

- Added a dedicated Traffic page using WG-Easy WireGuard peer counters.
- Successive samples derive live RX/TX rates without modifying the routing
  dataplane.
- Shows effective route/source and traffic per client, aggregate traffic by
  effective route, and current consumers for each outbound VPN profile.
- Main dashboard includes a compact live traffic summary.
- Traffic history is not persisted; schema remains v6.
