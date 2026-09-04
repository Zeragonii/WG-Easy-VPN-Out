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

## VPN Profile Library

VPN Router's VPN Clients area is a profile library designed for installations
with tens or hundreds of outbound VPN exits. Profiles can be searched and
filtered by provider, country, region, protocol and tags; sorted without extra
server requests; marked as favourites; tagged; and changed in bulk.

Bulk import accepts up to 200 OpenVPN `.ovpn` and WireGuard `.conf` files per
batch. Every file is passed through the same existing configuration validation
and profile-intelligence path, imports start with automatic connection disabled,
and matching kill-switch routing groups can be created automatically.

Routing Groups use compact collapsed summaries by default so large profile
libraries do not turn the routing page into an endless wall of cards. Expanding
a group reveals the existing health, DNS, transition and management details.

## Interface appearance

VPN Router includes an optional animated network-style particle background.
The effect is enabled by default and can be disabled under
**Settings → Appearance**. It is rendered locally with no third-party runtime
dependency, sits behind the interface without receiving pointer events, pauses
when the tab is hidden, respects the browser's reduced-motion preference, and
preserves its particle state across normal page navigation within the same
browser tab.

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

## Releases and changelog

The README documents the **current** project and deployment model rather than
duplicating historical patch notes.

- [GitHub Releases](https://github.com/Zeragonii/WG-Easy-VPN-Out/releases)
  contains the release notes for each tagged version.
- [CHANGELOG.md](CHANGELOG.md) contains the complete searchable version
  history in the repository.

On each push to `main`, the release workflow reads `VERSION`, validates the
tree, publishes the container, creates the matching `v<VERSION>` tag when
needed, and creates the GitHub Release from that version's `CHANGELOG.md`
section. The changelog remains the single source of truth for release notes.
GHCR image names are normalized to lowercase automatically during publishing.

A manual **Backfill historical GitHub Releases** workflow is also available for
creating missing Releases from older `v*` tags. It defaults to dry-run mode,
skips Releases that already exist, and uses a short historical fallback note
only when an old tag has no exact per-version changelog section.
