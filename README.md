# Security Harbor Agent

> 🇬🇧 English version: [README.en.md](README.en.md)

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
                                  OpenVPN, rsyslog, Suricata, HAProxy (SNI)
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
(default `0.0.0.0:8443` — alla gränssnitt; nftables håller porten LAN-only
via HARD WAN DROP, så API:t är nåbart på vilken LAN-IP servern än har),
`--webui-dir` (default `/var/lib/security-harbor/webui`, statiska filer för
webb-GUI:t), `--dry-run`, `--version`.

## Installation

Enrads-installation direkt från GitHub (self-bootstrap — hämtar den senaste
signerade release-bunten och kör den):

```bash
curl -fsSL https://raw.githubusercontent.com/walker42195/security-harbor-agent/main/install.sh | sudo bash
```

Läget (router/gateway eller enkelkorts-/värddator) väljs interaktivt; lägg
till `-s -- --mode=gateway` (eller `--mode=host`) för att hoppa över frågan.
I gateway-läge listas nätverkskorten (namn, nuvarande IP, länkstatus) innan
du väljer WAN-gränssnitt.

Eller bygg en egen bunt och installera lokalt:

```bash
./build_release.sh          # cross-kompilerar allt + bygger webb-GUI:t till ./dist/
scp -r dist/ user@brandvägg:/tmp/security-harbor-install
ssh user@brandvägg
cd /tmp/security-harbor-install && sudo ./install.sh
```

`install.sh` är **idempotent** (kan köras om för att uppdatera). Den
installerar systempaket (nftables, Kea, Unbound, WireGuard, OpenVPN,
Suricata, tcpdump, HAProxy), skapar det körande systemkontot
`security-harbor`, systemd-enheterna, polkit-reglerna och webb-GUI:t, och
startar (eller startar om) agenten.

## Uppdatering

**Via GUI:t (rekommenderas):** Settings → Uppdateringar → **Kontrollera** →
**Ladda ner** → **Uppgradera**. Agenten hämtar den senaste release-bunten,
verifierar den med **SHA256 + Ed25519-signatur** mot en inbyggd publik nyckel,
och en privilegierad root-installer (som om-verifierar signaturen som root)
byter binärer + webb-GUI och startar om agenten. Konfiguration, databas och
nycklar i `/var/lib/security-harbor` bevaras. Har du möjlighet, ta en snapshot
av maskinen före en uppgradering.

**Manuellt:** kör om enrads-installationen ovan (self-bootstrap hämtar senaste
releasen), eller `git pull` + `./build_release.sh` + `sudo ./dist/install.sh`.

Release-signering: `build_release.sh` signerar tarbollen med `cmd/security-harbor-sign`
(Ed25519). Den privata nyckeln hålls utanför repot; den publika är inbyggd i
agenten (`pkg/updater`). Se `SECURITY.md` för hotmodellen bakom
självuppdateringen.

## Avinstallation

Enrads-avinstallation direkt från GitHub:

```bash
# Ta bort agenten, tjänsterna, systemd-enheterna och polkit-reglerna
# (config/nycklar i /var/lib/security-harbor och systempaketen lämnas kvar):
curl -fsSL https://raw.githubusercontent.com/walker42195/security-harbor-agent/main/uninstall.sh | sudo bash

# Fullständig rensning (--purge): tar DESSUTOM bort /var/lib/security-harbor
# (all config, alla nycklar, alla användarkonton — kan inte ångras utan
# backup), systemkontot security-harbor och de installerade systempaketen.
# Ger en helt färsk maskin inför en ny installation:
curl -fsSL https://raw.githubusercontent.com/walker42195/security-harbor-agent/main/uninstall.sh | sudo bash -s -- --purge
```

`--purge` frågar efter en `ja`-bekräftelse innan config/nycklar raderas. Har
du redan bunten lokalt kan du köra `sudo ./uninstall.sh [--purge]` direkt.

## Delsystem (`cmd/`)

De flesta binärerna är hjälpprocesser som körs av huvuddaemonen via
privilegie-separerade systemd-oneshot-tjänster (se `SECURITY.md`), inte av
en operatör direkt:

- `security-harbor-agent` — huvuddaemonen.
- `security-harbor-nmap-runner` / `security-harbor-tcpdump-runner` — körs
  som root via `systemctl start --wait` när huvuddaemonen (som saknar
  `NoNewPrivileges`-undantag) behöver en portscan/paketfångst.
- `security-harbor-sign` — signerar release-artefakter vid bygge (Ed25519).
  Byggs och används lokalt av `build_release.sh`, ingår inte i den
  installerade bunten.

## Funktioner (urval)

- Zonbaserad brandvägg (nftables), Safe Apply med automatisk rollback.
- VLAN, DHCP per VLAN (Kea), outbound NAT, port forwarding (DNAT), NAT-reflektion.
- WireGuard + OpenVPN (egen PKI), lokal DNS (Unbound) med blocklistor/DoT,
  hot-listor och GeoIP-landsblockering.
- SNI-baserad routning (HAProxy, passthrough) — ta emot TLS på en valfri port
  och dirigera till olika interna servrar efter efterfrågat värdnamn.
- IDS (Suricata, passivt läge) med Säkerhetshändelser och valfri auto-blockering.
- Loggning/diagnostik, centraliserad syslog, multianvändare/roller, HTTPS-GUI.
- Signerad in-GUI-självuppdatering (SHA256 + Ed25519), backup/återställning,
  fabriksåterställning, enkelkorts-/värddatorläge.

⚠️ **Inte pentestat av en oberoende tredje part ännu** — se `SECURITY.md`
och security.novabase.se för aktuell status. Kör inte som enda skydd mot
internet förrän en extern granskning genomförts.
