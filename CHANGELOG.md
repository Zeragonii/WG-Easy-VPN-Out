
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
