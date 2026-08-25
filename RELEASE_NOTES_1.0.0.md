# WG-Easy-VPN-Out v1.0.0

The first stable release.

WG-Easy-VPN-Out adds pfSense-style per-client outbound VPN policy routing around
WG-Easy without requiring a separate router OS.

## Highlights

- Discover WG-Easy clients and assign each to a routing group.
- Route groups through Default WAN or outbound OpenVPN profiles.
- nftables policy routing with deterministic marks/tables.
- Kill-switch or WAN fallback per routing group.
- Persistent OpenVPN auto-connect and exponential recovery.
- Local/private-network bypass so routed clients retain LAN access.
- Backup/restore, schema migrations, diagnostics and update awareness.

## Validation

The final 1.0 release candidate passed:

- fresh-install testing
- restore from an existing deployment backup
- restored VPN/routing recovery
- deliberate broken-VPN timeout and retry testing
- stale managed routing cleanup
- kill-switch verification
- 11/11 live release-readiness checks

## AI development disclosure

This project was developed with substantial assistance from OpenAI ChatGPT for
architecture, implementation, debugging, documentation, test design and release
planning. The project maintainer directed requirements, deployment, validation,
testing and release decisions. The README contains the full disclosure.
