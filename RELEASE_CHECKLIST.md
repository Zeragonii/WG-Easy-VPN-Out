# 1.0 Release Checklist

Use this checklist before tagging `v1.0.0`.

## Deployment

- [ ] Build/publish the image successfully in GitHub Actions.
- [x] Deploy a clean instance with an empty persistent `/data` volume.
- [x] Confirm first startup creates schema v1 and the admin login works.
- [x] Upgrade an existing 0.9.x `/data` volume without data loss.
- [ ] Confirm the dashboard reports the image-owned version.

## VPN runtime

- [x] Confirm each enabled OpenVPN profile reconnects after container redeploy.
- [ ] Confirm tunnel interface, tunnel IPv4 and pushed gateway are populated.
- [ ] Confirm exit-IP observability updates asynchronously.
- [x] Break one VPN profile deliberately and confirm connecting timeout/retry.
- [ ] Restore the valid config and confirm recovery.

## Policy routing

- [ ] Confirm each assigned WG-Easy client exits through its selected target.
- [ ] Confirm private/RFC1918 destinations remain locally reachable.
- [ ] Confirm kill-switch blocks internet traffic when its VPN is unavailable.
- [ ] Confirm WAN fallback uses the main WAN when configured.
- [x] Delete/recreate a routing group and confirm no stale managed rule/table remains.

## Backup / restore

- [ ] Create a backup without SECRET_KEY and inspect it.
- [ ] Create a backup with SECRET_KEY and verify warning/acknowledgement.
- [x] Restore a valid backup and confirm profiles/groups/assignments return.
- [x] Confirm enabled VPNs recover after restore/redeploy.
- [ ] Confirm an intentionally invalid archive is rejected before live state changes.

## Diagnostics / security

- [x] Run Diagnostics → Release readiness with zero failed checks.
- [ ] Download diagnostics and verify it contains no passwords, SECRET_KEY,
      VPN config contents, or WG-Easy credentials.
- [ ] Confirm Backup & Restore and Diagnostics require authentication.
- [ ] Confirm no Docker socket or privileged container mode is required.

## Release

- [x] Set `VERSION` to `1.0.0`.
- [x] Update `CHANGELOG.md`.
- [ ] Commit and push.
- [ ] Create Git tag `v1.0.0`.
- [ ] Confirm GHCR publishes `latest`, `1.0.0`, and `1.0` tags.
- [ ] Confirm dashboard update-awareness considers `1.0.0` newer than 0.9.x.
