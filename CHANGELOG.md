# Changelog

## 1.5.5

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

## 1.5.4

### VPN client list status semantics

- Unused enabled on-demand VPN profiles now display **Offline** in the VPN
  Clients list instead of inheriting historical OpenVPN failure state.
- **Failed** is reserved for profiles that are actually required/expected to
  be connected and have genuinely failed.
- Individual profile detail pages retain the richer **Standby** state and real
  failure diagnostics.
- No schema, routing, DNS, lifecycle, or provider-adapter behavior changes.

## 1.5.3

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

## 1.5.2

### Documentation transparency

- Moved the existing **AI-assisted development** disclosure to the top of
  `README.md`, immediately after the project title.
- Preserved the disclosure text unchanged.
- Future appended release notes can remain below it without moving the
  disclosure again.
- No application, routing, runtime, schema, or container behavior changes.

## 1.5.1

### On-demand standby state

- Intentional disconnects of unused enabled on-demand profiles display
  **Standby** instead of Failed.
- Historical OpenVPN log errors are suppressed while a profile is intentionally
  in standby.
- Genuine connection failures while a profile is required remain failures.
- Diagnostics report standby consistently.

### DNS validation fix

- Fixed forced-DNS manual probes using a different routing path from WG-Easy
  client traffic.
- Explicit resolver probes now temporarily mirror the routing group's policy
  table with a narrow source+destination `ip rule`.
- Temporary probe rules are removed in `finally` cleanup.
- Client DNS interception/routing behavior itself is unchanged.

## 1.5.0

### On-demand VPN connections

- Added schema v5 VPN profile `connection_policy`.
- Added **Always connected** and **On demand** policies.
- Requirement is assignment-driven rather than handshake-driven.
- Required on-demand VPNs are reconciled synchronously during app startup.
- Assignment changes use connect-before-switch handover.
- Failed target VPN startup leaves the existing assignment unchanged.
- Unused on-demand profiles disconnect after a 60-second idle grace period.
- VPN resilience no longer reconnects unused on-demand profiles.
- Added connection policy to UI, diagnostics and backup/restore.
- Existing profiles default to **Always connected**.

## 1.4.2

### Provider adapter framework

- Refactored profile intelligence into generic parsing plus provider adapters.
- Added generic fallback adapter for unknown providers.
- Moved PIA detection and region parsing into a dedicated PIA adapter.
- Added provider detection confidence and reason metadata.
- Added provider capability metadata for future provider-specific features.
- PIA adapter exposes DNS presets for future reuse without changing current
  routing behavior.
- No schema migration and no routing/runtime behavior changes.

## 1.4.1

### Region hint parsing fixes

- Added support for country-only PIA endpoint names such as
  `ireland.privacy.network`.
- Recognise PIA `-so` endpoint suffixes as **Streaming Optimized**.
- Avoid redundant output such as `Netherlands · Netherlands So`.
- No routing, schema, provider-runtime, or configuration changes.

## 1.4.0

### Provider metadata & profile intelligence

- Added read-only VPN configuration intelligence.
- Added conservative provider detection for common VPN endpoint patterns.
- Added endpoint, port, protocol/transport, auth, TLS, cipher and remote-count
  metadata for OpenVPN profiles.
- Added endpoint/provider metadata parsing for WireGuard configs.
- Added conservative region hints from unambiguous endpoint naming.
- Added richer VPN Clients list and Profile Intelligence detail card.
- Added derived profile metadata to diagnostics.
- No schema migration; configuration files remain the source of truth.
- No provider-specific routing automation or configuration rewriting.

## 1.3.0

### DNS policy & leak prevention

- Added schema v4 routing-group DNS policy fields.
- Added per-group Existing / PIA / Custom DNS modes.
- Added transparent UDP/TCP port 53 redirection for assigned WG-Easy clients.
- Forced DNS is marked before RFC1918 bypass so PIA DNS at `10.0.0.242`
  correctly follows the VPN routing table.
- DNS policy follows VPN kill-switch/fallback behavior.
- Added explicit resolver validation through the selected VPN tunnel.
- Added DNS policy details to Routing Group Health and diagnostics.
- Added DNS policy fields to backup/restore with backward-compatible defaults.
- DNS-over-HTTPS remains intentionally out of scope.

## 1.2.2

### DNS leak probe result handling

- Fixed false `Unavailable` results caused by treating bash.ws trigger ping
  failures as DNS-generation failures.
- Ping return codes are now intentionally ignored, matching the upstream
  bash.ws dnsleaktest implementation.
- Resolver observation from the bash.ws result endpoint is now the authoritative
  signal for whether DNS servers were detected.

## 1.2.1

### DNS leak probe fix

- Replaced tunnel-address-bound `dig` queries with `ping -I <VPN interface>`
  hostname triggers.
- DNS resolution is now left to the container's configured resolver path,
  avoiding the invalid source-routing pattern seen in v1.2.0.
- Removed the unnecessary `dig` dependency.
- Added `ping` to the container image and networking-tools preflight.

## 1.2.0

### Routing health

- Added schema v3 and persistent routing transition history.
- Routing Group Health now shows configured/effective exits and recent state
  transitions.
- Dashboard routing health shows DNS state and last transition time.

### DNS leak visibility

- Added tunnel-pinned DNS leak probes using bash.ws.
- Added resolver IP/country/ASN visibility.
- Added conservative “No obvious leak” / “Potential DNS leak” health states.
- Added manual per-routing-group DNS tests.
- Added configurable automatic DNS probe interval (default 900 seconds).
- Added `dig` to the container image and release preflight.
- DNS remains observational only; v1.2.0 does not rewrite or enforce resolvers.

## 1.1.0

### First-run setup

- Added one-time setup-token protection for unconfigured installations.
- Added browser-based administrator creation.
- Added WG-Easy connection validation during setup.
- Existing deployments remain backward compatible through legacy environment
  import.

### Application settings

- Added schema v2 and persistent `app_settings`.
- Added encrypted WG-Easy credentials.
- Added Settings UI for WG-Easy, routing, resilience and observability.
- Added WG-Easy connection test and administrator account management.
- Runtime managers reload applicable settings without a container restart.
- Reduced the recommended Compose environment to deployment-level values.
- Added settings to backup/restore.


# Changelog

## 1.0.0

First stable OpenVPN release.

### Stable feature set

- WG-Easy client discovery and status tracking.
- Outbound OpenVPN profile import, activation and persistent auto-connect.
- Per-client routing groups with nftables policy routing.
- Deterministic fwmark/routing-table allocation.
- VPN kill-switch and WAN fallback modes.
- Local/private-network bypass for policy-routed clients.
- Automatic routing reconciliation.
- Exponential VPN retry/recovery with connecting timeout.
- Async exit-IP observability and GitHub update awareness.
- Portable backup/restore with optional SECRET_KEY inclusion.
- Versioned database migrations.
- Hardened restore validation, staging and rollback.
- Redacted diagnostics and release-readiness preflight.

### Release validation

The final release candidate was tested with:

- a fresh install
- restore from an existing deployment backup
- successful restored VPN reconnection
- deliberate broken-VPN timeout/retry behavior
- stale policy-rule/table cleanup
- kill-switch operation
- 11/11 release-readiness checks passing

### Development transparency

OpenAI ChatGPT was used extensively as an AI development assistant throughout
the project. See the README's **AI-assisted development** section for details.

## 0.9.3b

- Fixed VPN resilience retry accounting: successfully spawning an OpenVPN
  process is no longer treated as a successful VPN connection.
- Failure counts now survive subsequent retry starts and accumulate across
  repeated connecting timeouts, allowing exponential backoff to work as
  intended.
- `last_success_at` is now updated only after the resilience manager actually
  observes a connected tunnel.

## 0.9.3a

- Fixed Diagnostics release-readiness JavaScript being emitted inside the
  document title/head block before the preflight controls existed.
- The Run preflight button now attaches its click handler after the page
  content is rendered.

## 0.9.3

Release-candidate hygiene and preflight validation.

- Added read-only release-readiness checks in Diagnostics.
- Checks schema, persistent storage, required networking tools, background
  services, VPN config presence, deterministic routing allocations, policy
  rules, nftables state, enabled OpenVPN health, assignment integrity and
  basic SECRET_KEY hygiene.
- Added a documented 1.0 release checklist.
- Consolidated the pre-1.0 change history.

## 0.9.2

- Added versioned database schema migrations.
- Added schema compatibility to backups and diagnostics.
- Hardened ZIP/path/entity/reference/allocation validation.
- Added staged restore writes and rollback recovery.

## 0.9.1

- Added graceful lifecycle handling for background services.
- Added post-restore state reconciliation.
- Expanded diagnostics with service and retry state.
- Added public exit-IP runtime API.

## 0.9.0

- Added stale policy-rule/table cleanup.
- Added OpenVPN connecting timeout and retry recovery.
- Added authenticated diagnostics and redacted export.
- Reduced cross-service reliance on private runtime helpers.

## 0.8.0

- Added portable backup and restore.
- Added optional SECRET_KEY inclusion with explicit risk acknowledgement.
- Added backup inspection and restore validation.

## 0.7.x

- Added observability dashboard and async exit-IP probing.
- Added repo-owned VERSION and GHCR image version reporting.
- Added GitHub update awareness and configurable cache.
- Added flexible multi-component/alphanumeric version comparison.
- Fixed local/private network bypass for policy-routed clients.

## 0.6.x

- Added automatic VPN retry/recovery with exponential backoff.
- Expanded operational dashboard summaries.

## 0.5.x

- Added persistent WG-Easy client-to-routing-group assignments.
- Added automatic routing reconciliation on tunnel state changes.

## 0.4.0

- Added nftables-based policy routing, deterministic marks/tables,
  kill-switch and WAN fallback.

## 0.3.x

- Added outbound OpenVPN profile import, activation, runtime state,
  auto-connect and probe routing.

## 0.2.x

- Added WG-Easy client discovery and live client status.

## 0.1.0

- Initial Flask/Gunicorn application foundation.
