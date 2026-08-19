# Security Harbor Agent

Brandväggs- och nätverksappliance-daemon för Linux, skriven i Go. Förvandlar
en vanlig Linux-dator med flera nätverkskort till en brandvägg med
router-, DHCP-, DNS-, VPN- och IDS-funktioner, administrerad från
[security-harbor-gui](https://github.com/walker42195/security-harbor-gui)
(nativ Flutter-app eller webbläsare).

Se [security.novabase.se](https://security.novabase.se) för status och
nedladdning, och `SECURITY.md` i det här repot för säkerhetsmodellen.

## Arkitektur

Fyra strikt separerade lager, så att GUI:t aldrig behöver känna till
nftables-syntax eller shell-kommandon:

```
Flutter-app (mobil/desktop/webb)
        ↓ HTTPS + Bearer-token
Management API (pkg/api)       — autentisering, RBAC, Safe Apply
        ↓
Configuration Engine (pkg/engine) — deklarativ modell, candidate/running-state
        ↓
Linux-backend (pkg/adapter/*)  — nftables, Kea DHCP, Unbound, WireGuard,
                                  OpenVPN, rsyslog, Suricata
```

Konfigurationen (`pkg/config/model.go`) är en enda deklarativ struct som
seriealiseras till `running.json`/`candidate.json`. Ändringar går via
**Safe Apply**: `candidate → apply → confirm`, med automatisk rollback om
administratören blir utelåst (se `pkg/engine/engine.go`).

## Bygg & kör

```bash
go build ./...
go vet ./...
go test ./...
```

Kör lokalt (kräver root för nftables/DHCP/etc. i praktiken, se
`systemd/security-harbor-agent.service` för den härdade produktionsprofilen):

```bash
go run ./cmd/security-harbor-agent --data-dir ./data --bind 0.0.0.0:8443
```

Flaggor: `--data-dir` (default `/var/lib/security-harbor`), `--bind`
(default `10.0.0.163:8443`), `--webui-dir` (default
`/var/lib/security-harbor/webui`, statiska filer för webb-GUI:t), `--dry-run`.

## Installation

En färdig, idempotent installer finns för Ubuntu/Debian-liknande system:

```bash
./build_release.sh          # cross-kompilerar allt till ./dist/
scp -r dist/ user@brandvägg:/tmp/security-harbor-install
ssh user@brandvägg
cd /tmp/security-harbor-install && sudo ./install.sh
```

`install.sh` installerar systempaket (nftables, Kea, Unbound, WireGuard,
OpenVPN, Suricata, tcpdump), skapar det körande systemkontot
`security-harbor`, systemd-enheterna och polkit-reglerna, samt startar
agenten. Laddar INTE ner något från nätet självt utöver `apt`/
`suricata-update` — ingen OTA-funktion finns i det här skedet, se
`SECURITY.md`.

## Delsystem (`cmd/`)

De flesta binärerna är hjälpprocesser som körs av huvuddaemonen via
privilegie-separerade systemd-oneshot-tjänster (se `SECURITY.md`), inte av
en operatör direkt:

- `security-harbor-agent` — huvuddaemonen.
- `security-harbor-nmap-runner` / `security-harbor-tcpdump-runner` — körs
  som root via `systemctl start --wait` när huvuddaemonen (som saknar
  `NoNewPrivileges`-undantag) behöver en portscan/paketfångst.
- `security-harbor-reset-password` / `security-harbor-emergency-restore` —
  manuella "break glass"-verktyg, körs via SSH direkt på servern, aldrig
  som en långlivad tjänst.

## Fas-status

Projektet byggs enligt en 14-fasig plan. Status per 2026-08-19:

| Fas | Namn | Status |
|---|---|---|
| 0–7 | Säkerhetsgrund t.o.m. Avancerad Firewall Engine | Klart |
| 8 | Loggning, Övervakning & Diagnostics | Klart |
| 9 | IDS/IPS & Security Events | Klart (MVP — passivt IDS-läge, ej inline) |
| 10 | Appliance Lifecycle, Backup & Installation | Klart (utan OTA, se avgränsning nedan) |
| 11 | IPv6, Multi-WAN & High Availability | Uppskjuten (kräver ny policy-routing-infrastruktur + en tredje testlänk för verklig failover-verifiering) |
| 12 | Hårdning, Pentest & Release | Pågående |
| 13 | Enkelkorts-läge (Host Firewall) | Ej påbörjad |

**Explicit avgränsning:** ingen OTA/automatisk självuppdatering finns eller
är planerad i nuvarande form — uppdatering sker manuellt (`git pull` +
bygg + `install.sh`). Se `SECURITY.md` för varför.

⚠️ **Inte pentestat av en oberoende tredje part ännu** — se
`SECURITY.md` och security.novabase.se för aktuell status. Kör inte som
enda skydd mot internet förrän en extern granskning genomförts.
