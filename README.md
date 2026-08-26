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
