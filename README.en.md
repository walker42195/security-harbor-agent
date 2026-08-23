# Security Harbor Agent

> 🇸🇪 Svensk version: [README.md](README.md)

A firewall and network-appliance daemon for Linux, written in Go. It turns an
ordinary Linux machine with multiple network cards into a firewall with
routing, DHCP, DNS, VPN and IDS features, administered from
[security-harbor-gui](https://github.com/walker42195/security-harbor-gui)
(native Flutter app or web browser).

See [security.novabase.se](https://security.novabase.se) for status and
downloads, and `SECURITY.md` in this repo for the security model.

## Architecture

Four strictly separated layers, so the GUI never has to know about nftables
syntax or shell commands:

```
Flutter app (mobile/desktop/web)
        ↓ HTTPS + Bearer token
Management API (pkg/api)       — authentication, RBAC, Safe Apply
        ↓
Configuration Engine (pkg/engine) — declarative model, candidate/running state
        ↓
Linux backend (pkg/adapter/*)  — nftables, Kea DHCP, Unbound, WireGuard,
                                  OpenVPN, rsyslog, Suricata, HAProxy (SNI)
```

The configuration (`pkg/config/model.go`) is a single declarative struct
serialized to `running.json`/`candidate.json`. Changes go through **Safe
Apply**: `candidate → apply → confirm`, with automatic rollback if the
administrator gets locked out (see `pkg/engine/engine.go`).

## Build & run

```bash
go build ./...
go vet ./...
go test ./...
```

Run locally (needs root for nftables/DHCP/etc. in practice; see
`systemd/security-harbor-agent.service` for the hardened production profile):

```bash
go run ./cmd/security-harbor-agent --data-dir ./data --bind 0.0.0.0:8443
```

Flags: `--data-dir` (default `/var/lib/security-harbor`), `--bind` (default
`0.0.0.0:8443` — all interfaces; nftables keeps the port LAN-only via the
HARD WAN DROP, so the API is reachable on whatever LAN IP the server has),
`--webui-dir` (default `/var/lib/security-harbor/webui`, static files for the
web GUI), `--dry-run`, `--version`.

## Installation

One-line install straight from GitHub (self-bootstrap — fetches the latest
signed release bundle and runs it):

```bash
curl -fsSL https://raw.githubusercontent.com/walker42195/security-harbor-agent/main/install.sh | sudo bash
```

The mode (router/gateway or single-NIC/host) is chosen interactively; add
`-s -- --mode=gateway` (or `--mode=host`) to skip the prompt. In gateway mode
the network cards are listed (name, current IP, link state) before you pick
the WAN interface.

Or build your own bundle and install locally:

```bash
./build_release.sh          # cross-compiles everything + builds the web GUI into ./dist/
scp -r dist/ user@firewall:/tmp/security-harbor-install
ssh user@firewall
cd /tmp/security-harbor-install && sudo ./install.sh
```

`install.sh` is **idempotent** (re-run it to update). It installs system
packages (nftables, Kea, Unbound, WireGuard, OpenVPN, Suricata, tcpdump,
HAProxy), creates the `security-harbor` service account, the systemd units,
the polkit rules and the web GUI, and starts (or restarts) the agent.

## Updating

**Via the GUI (recommended):** Settings → Updates → **Check** → **Download**
→ **Upgrade**. The agent fetches the latest release bundle, verifies it with
**SHA256 + an Ed25519 signature** against a built-in public key, and a
privileged root installer (which re-verifies the signature as root) swaps the
binaries + web GUI and restarts the agent. Configuration, database and keys in
`/var/lib/security-harbor` are preserved. Take a VM snapshot before upgrading.

**Manually:** re-run the one-line install above (self-bootstrap fetches the
latest release), or `git pull` + `./build_release.sh` + `sudo ./dist/install.sh`.

Release signing: `build_release.sh` signs the tarball with
`cmd/security-harbor-sign` (Ed25519). The private key is kept outside the repo;
the public key is built into the agent (`pkg/updater`). See `SECURITY.md` for
the threat model behind self-updates.

## Uninstalling

One-line uninstall straight from GitHub:

```bash
# Remove the agent, services, systemd units and polkit rules
# (config/keys in /var/lib/security-harbor and the system packages are kept):
curl -fsSL https://raw.githubusercontent.com/walker42195/security-harbor-agent/main/uninstall.sh | sudo bash

# Full wipe (--purge): ALSO removes /var/lib/security-harbor (all config, all
# keys, all user accounts — cannot be undone without a backup), the
# security-harbor system account and the installed system packages. Gives a
# completely fresh machine for a new installation:
curl -fsSL https://raw.githubusercontent.com/walker42195/security-harbor-agent/main/uninstall.sh | sudo bash -s -- --purge
```

`--purge` asks for a `ja` (yes) confirmation before config/keys are deleted.
If you already have the bundle locally you can run `sudo ./uninstall.sh
[--purge]` directly.

## Subsystems (`cmd/`)

Most binaries are helper processes run by the main daemon via
privilege-separated systemd oneshot services (see `SECURITY.md`), not directly
by an operator:

- `security-harbor-agent` — the main daemon.
- `security-harbor-nmap-runner` / `security-harbor-tcpdump-runner` — run as
  root via `systemctl start --wait` when the main daemon (which has no
  `NoNewPrivileges` exemption) needs a port scan / packet capture.
- `security-harbor-sign` — signs release artifacts at build time (Ed25519).
  Built and used locally by `build_release.sh`; not part of the installed
  bundle.

## Features (selection)

- Zone-based firewall (nftables), Safe Apply with automatic rollback.
- VLANs, per-VLAN DHCP (Kea), outbound NAT, port forwarding (DNAT), NAT reflection.
- WireGuard + OpenVPN (own PKI), local DNS (Unbound) with blocklists/DoT,
  threat feeds and GeoIP country blocking.
- SNI-based routing (HAProxy, passthrough) — accept TLS on any port and route
  to different internal servers by requested hostname.
- IDS (Suricata, passive mode) with a Security Events panel and optional
  auto-blocking.
- Logging/diagnostics, centralized syslog, multi-user/roles, HTTPS GUI.
- Signed in-GUI self-update (SHA256 + Ed25519), backup/restore, factory reset,
  single-NIC/host mode.

⚠️ **Not independently penetration-tested yet** — see `SECURITY.md` and
security.novabase.se for current status. Do not run it as your only protection
against the internet until an external review has been carried out.
