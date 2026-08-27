#!/bin/bash
# Security Harbor Agent - installer.
#
# Två körsätt:
#   1) Från en redan uppackad installationsbunt (byggd med
#      ./build_release.sh, se dist/) - binärerna ligger bredvid skriptet.
#   2) Fristående, hämtad direkt från GitHub (self-bootstrap): om
#      binärerna INTE ligger bredvid skriptet laddar det ner senaste
#      GitHub Release-tarbollen automatiskt och fortsätter därifrån. Gör
#      ett riktigt en-rads-installationskommando möjligt:
#
#        curl -fsSL https://raw.githubusercontent.com/walker42195/security-harbor-agent/main/install.sh | sudo bash
#
#      (lägg till "-s -- --mode=host" för att slippa den interaktiva
#      läge-frågan). Detta är INTE en OTA/auto-update-funktion - skriptet
#      laddar bara ner EN gång, vid en av en människa manuellt startad
#      installation, aldrig automatiskt av den körande agenten själv.
#
# Idempotent: kan köras om på en redan installerad maskin utan att
# förstöra något (paket/användare/kataloger skapas bara om de saknas).
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "Måste köras som root (sudo ./install.sh)" >&2
  exit 1
fi

GITHUB_REPO="walker42195/security-harbor-agent"
DATA_DIR="/var/lib/security-harbor"
CONF_DIR="/etc/security-harbor"
BIN_DIR="/usr/local/bin"

MODE=""
WAN_DEVICE=""
for arg in "$@"; do
  case "$arg" in
    --mode=*) MODE="${arg#*=}" ;;
    --wan-device=*) WAN_DEVICE="${arg#*=}" ;;
    -h|--help)
      echo "Användning: $0 [--mode=gateway|host] [--wan-device=<namn>]"
      echo "  --mode        Hoppa över den interaktiva frågan om driftläge."
      echo "  --wan-device  (Endast gateway-läge) Gränssnittsnamn för WAN-sidan"
      echo "                i failsafe-regelsetet. Auto-detekteras/frågas annars."
      exit 0
      ;;
  esac
done

# --- Self-bootstrap: hämta från GitHub om binärerna inte finns lokalt ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ ! -f "$SCRIPT_DIR/security-harbor-agent" ]; then
  echo "=== 0. Hämtar senaste release från GitHub (self-bootstrap) ==="
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  ARCHIVE_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/security-harbor-dist.tar.gz"
  if ! curl -fsSL "$ARCHIVE_URL" -o "$TMP_DIR/dist.tar.gz"; then
    echo "Kunde inte hämta $ARCHIVE_URL" >&2
    echo "(kräver att repot är publikt och att en release med den bifogade filen finns)" >&2
    exit 1
  fi
  tar -xzf "$TMP_DIR/dist.tar.gz" -C "$TMP_DIR"
  SCRIPT_DIR="$TMP_DIR"
  echo "-> Uppackat till $TMP_DIR"
fi

for bin in security-harbor-agent security-harbor-nmap-runner security-harbor-tcpdump-runner \
           security-harbor-network-runner; do
  if [ ! -f "$SCRIPT_DIR/$bin" ]; then
    echo "Hittar inte $SCRIPT_DIR/$bin - trasig bunt/release" >&2
    exit 1
  fi
done

# --- Läge: router (gateway) eller denna dator (host)? ---
if [ -z "$MODE" ]; then
  if [ -r /dev/tty ]; then
    echo ""
    echo "Vilken typ av installation är det här?"
    echo "  [1] Router/brandvägg (flera nätverkskort, WAN+LAN, DHCP/NAT/VPN/IDS)"
    echo "  [2] Denna dator (ett nätverkskort, bara skydda den här datorn)"
    read -r -p "Val [1]: " CHOICE </dev/tty
    case "$CHOICE" in
      2) MODE="host" ;;
      *) MODE="gateway" ;;
    esac
  else
    echo "Ingen terminal tillgänglig för interaktiv fråga - defaultar till gateway-läge." >&2
    echo "(ange --mode=host explicit om det önskas i en icke-interaktiv installation)" >&2
    MODE="gateway"
  fi
fi
if [ "$MODE" != "gateway" ] && [ "$MODE" != "host" ]; then
  echo "Ogiltigt --mode: $MODE (måste vara 'gateway' eller 'host')" >&2
  exit 1
fi
echo "-> Installerar i läge: $MODE"

echo "=== 1. Installerar systempaket ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
if [ "$MODE" = "host" ]; then
  # Enkelkorts-/värddator-läge (Fas 13): ingen DHCP-server, ingen
  # rekursiv DNS-resolver, ingen VPN-server, ingen IDS - det här skyddar
  # EN dator, det kör inte en gateway-roll åt andra.
  apt-get install -y \
    nftables \
    tcpdump \
    nmap \
    bind9-dnsutils \
    rsyslog \
    polkitd \
    jq
else
  apt-get install -y \
    nftables \
    chrony \
    kea-dhcp4-server \
    unbound \
    wireguard-tools \
    openvpn \
    haproxy \
    tcpdump \
    nmap \
    bind9-dnsutils \
    suricata \
    suricata-update \
    rsyslog \
    polkitd \
    jq
fi

echo "=== 2. Skapar systemanvändare/grupp 'security-harbor' ==="
if ! getent group security-harbor >/dev/null; then
  groupadd --system security-harbor
fi
if ! id -u security-harbor >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin \
    --gid security-harbor security-harbor
fi
# _kea-gruppen skapas av kea-dhcp4-server-paketet (gateway-läge) - krävs
# för att läsa DHCP-lease-databasen (DNS.DHCPHostnameRegistration).
if getent group _kea >/dev/null; then
  usermod -a -G _kea security-harbor
fi
# ... och omvänt: kea-dhcp4-server körs som _kea, men /etc/kea chgrupas
# nedan till security-harbor (för att agenten ska kunna skriva configen dit)
# med läge 770 - utan att _kea är MEDLEM i den gruppen kan den inte ens
# traversera katalogen för att öppna kea-dhcp4.conf, även om filen själv är
# världsläsbar. Upptäckt skarpt 2026-08-24: Kea-tjänsten fastnade i
# "failed" med "Unable to open file /etc/kea/kea-dhcp4.conf" trots att
# filen fanns och innehöll giltig JSON.
if id -u _kea >/dev/null 2>&1; then
  usermod -a -G security-harbor _kea
fi

echo "=== 3. Skapar kataloger ==="
mkdir -p "$DATA_DIR" "$CONF_DIR"
chown -R security-harbor:security-harbor "$DATA_DIR" "$CONF_DIR"
chmod 700 "$DATA_DIR"

# Skrivrätt på de KONFIGURATIONSFILER agenten faktiskt behöver ändra i
# andra paket. ReadWritePaths i systemd-enheten räcker INTE: den tar bara
# bort systemds egen skrivspärr (ProtectSystem=strict), vanliga
# fil-rättigheter gäller fortfarande - och agenten kör som den opriviligerade
# användaren security-harbor.
#
# Upptäckt skarpt 2026-08-20: att slå på IDS i GUI:t och trycka Applicera
# misslyckades alltid med "suricata: misslyckades skriva
# /etc/suricata/suricata.yaml: permission denied", eftersom filen är
# root:root 0644. Samma latenta fel fanns för centraliserad syslog, som
# skapar en ny fil i /etc/rsyslog.d (också root:root). Övriga adaptrar
# (unbound/kea/openvpn/wireguard) råkade fungera eftersom deras kataloger
# redan chownades vid en tidigare installation.
#
# Group-write i stället för att chowna filerna: paketens uppdateringar äger
# fortfarande sina filer, vi lägger bara till gruppåtkomst.
if [ -f /etc/suricata/suricata.yaml ]; then
  chgrp security-harbor /etc/suricata/suricata.yaml
  chmod g+w /etc/suricata/suricata.yaml
fi
if [ -d /etc/rsyslog.d ]; then
  chgrp security-harbor /etc/rsyslog.d
  chmod g+ws /etc/rsyslog.d
fi
# HAProxy (SNI-routning): agenten skriver /etc/haproxy/haproxy.cfg. Group-
# write på filen + traverserings-rätt på katalogen (samma mönster som
# suricata.yaml ovan). Agenten äger start/stopp av tjänsten, så den
# paket-aktiverade default-instansen inaktiveras nedan.
if [ -d /etc/haproxy ]; then
  chgrp security-harbor /etc/haproxy
  chmod g+x /etc/haproxy
  if [ -f /etc/haproxy/haproxy.cfg ]; then
    chgrp security-harbor /etc/haproxy/haproxy.cfg
    chmod g+w /etc/haproxy/haproxy.cfg
  fi
  # Agenten startar/stoppar haproxy.service via apply — den ska inte starta
  # automatiskt med paketets default-config vid boot.
  systemctl disable haproxy.service 2>/dev/null || true
  systemctl stop haproxy.service 2>/dev/null || true
fi

# Kea (DHCP), Unbound (DNS), OpenVPN och WireGuard: agenten SKAPAR/ersätter
# konfigurationsfiler i dessa kataloger. På en FÄRSK installation är de
# root:root, så tjänstekontot kan inte skriva där — upptäckt 2026-08-23 vid
# installation på en ny server ("kea-dhcp4.conf: permission denied", initial
# applicering failade). Kommentaren ovan noterade att dessa "råkade fungera"
# på en tidigare maskin bara för att katalogerna chownats manuellt då. Ge
# tjänstekontot grupp-skriv på katalogen (och ev. befintliga konfigfiler),
# samma mönster som suricata/haproxy. Dessa kataloger finns efter paket-
# installationen i gateway-läge (host-läge installerar dem inte).
# OBS: unbound skriver INTE i /etc/unbound utan i underkatalogen
# /etc/unbound/unbound.conf.d/ (defaultDir i pkg/adapter/dns/adapter.go) — den
# ligger också root:root efter paketinstallationen. Missades 2026-08-23:
# /etc/unbound blev grupp-skrivbar men conf.d inte, så DNS-applicering failade
# med "open .../security-harbor.conf: permission denied". Ta med conf.d i loopen.
for d in /etc/kea /etc/unbound /etc/unbound/unbound.conf.d /etc/openvpn /etc/wireguard /etc/chrony/conf.d; do
  if [ -d "$d" ]; then
    chgrp security-harbor "$d"
    chmod g+wx "$d"
  fi
done

echo "=== 4. Installerar binärer ==="
# Arkivera den UTGÅENDE versionen (om någon) innan den skrivs över, så att
# man kan rulla tillbaka till en av de senaste 3 via GUI:t/API:t om den nya
# versionen visar sig trasig. Delas med rollback-runner.sh - se den filen
# för hur en arkiverad version installeras tillbaka.
if [ -f "$SCRIPT_DIR/systemd/lib-archive-version.sh" ]; then
  # shellcheck source=systemd/lib-archive-version.sh
  . "$SCRIPT_DIR/systemd/lib-archive-version.sh"
  NEW_VERSION="$("$SCRIPT_DIR/security-harbor-agent" --version 2>/dev/null || true)"
  archive_current_version "$NEW_VERSION"
fi

for bin in security-harbor-agent security-harbor-nmap-runner security-harbor-tcpdump-runner; do
  install -m 0755 -o root -g root "$SCRIPT_DIR/$bin" "$BIN_DIR/$bin"
done

# Privilegierade root-runners (körs av security-harbor-update.service resp.
# security-harbor-rollback@.service, se systemd/update-runner.sh och
# systemd/rollback-runner.sh).
install -d -m 0755 /usr/local/lib/security-harbor
if [ -f "$SCRIPT_DIR/systemd/update-runner.sh" ]; then
  install -m 0755 -o root -g root "$SCRIPT_DIR/systemd/update-runner.sh" \
    /usr/local/lib/security-harbor/update-runner.sh
fi
if [ -f "$SCRIPT_DIR/systemd/rollback-runner.sh" ]; then
  install -m 0755 -o root -g root "$SCRIPT_DIR/systemd/rollback-runner.sh" \
    /usr/local/lib/security-harbor/rollback-runner.sh
fi
if [ -f "$SCRIPT_DIR/systemd/lib-archive-version.sh" ]; then
  install -m 0644 -o root -g root "$SCRIPT_DIR/systemd/lib-archive-version.sh" \
    /usr/local/lib/security-harbor/lib-archive-version.sh
fi
# Nätverkstillämparen (körs av security-harbor-network-apply.service). Ligger
# medvetet i /usr/local/lib/security-harbor och INTE i PATH — den är en
# hjälpare för root-oneshoten, inte ett kommando att köra för hand.
install -m 0755 -o root -g root "$SCRIPT_DIR/security-harbor-network-runner" \
  /usr/local/lib/security-harbor/security-harbor-network-runner

# Webb-GUI:t (flutter build web) buntas med releasen och deployas till
# agentens --webui-dir. Följer därmed alltid med agentuppdateringen. Ägs av
# tjänstekontot (agenten läser filerna; katalogen ligger i ReadWritePaths).
if [ -d "$SCRIPT_DIR/webui" ]; then
  echo "-> Deployar webb-GUI till $DATA_DIR/webui"
  install -d -m 0755 "$DATA_DIR/webui"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "$SCRIPT_DIR/webui/" "$DATA_DIR/webui/"
  else
    rm -rf "$DATA_DIR/webui"/*
    cp -a "$SCRIPT_DIR/webui/." "$DATA_DIR/webui/"
  fi
  chown -R security-harbor:security-harbor "$DATA_DIR/webui"
fi

echo "=== 5. Genererar failsafe-regelsetet ==="
if [ "$MODE" = "host" ]; then
  cp "$SCRIPT_DIR/systemd/security-harbor-failsafe-host.nft.tmpl" "$CONF_DIR/security-harbor-failsafe.nft"
else
  if [ -z "$WAN_DEVICE" ]; then
    DETECTED="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
    # Lista nätverkskorten med namn, nuvarande IP och länkstatus så man ser
    # vilket som är WAN (utsidan/internet). Ett WAN-kort utan inkopplad sladd
    # syns som "down" / utan IP — praktiskt när man installerar innan WAN
    # kopplas in.
    echo ""
    echo "Nätverkskort på den här servern:"
    for IFACE in $(ls /sys/class/net 2>/dev/null | grep -v '^lo$'); do
      IPADDR="$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{print $4}' | paste -sd', ' -)"
      STATE="$(cat "/sys/class/net/$IFACE/operstate" 2>/dev/null || echo '?')"
      printf "  - %-12s %-20s [%s]\n" "$IFACE" "${IPADDR:-(ingen IP)}" "$STATE"
    done
    echo "(WAN = kortet mot internet/utsidan. Det som du administrerar brandväggen"
    echo " genom, med serverns nuvarande IP, är LAN-sidan — välj INTE det som WAN.)"
    echo ""
    if [ -r /dev/tty ]; then
      read -r -p "WAN-gränssnittets namn för failsafe-regelsetet [${DETECTED:-ens18}]: " WAN_DEVICE </dev/tty
    fi
    WAN_DEVICE="${WAN_DEVICE:-${DETECTED:-ens18}}"
  fi
  echo "-> WAN-gränssnitt för failsafe: $WAN_DEVICE"
  sed "s/{{WAN_DEVICE}}/$WAN_DEVICE/g" \
    "$SCRIPT_DIR/systemd/security-harbor-failsafe-gateway.nft.tmpl" > "$CONF_DIR/security-harbor-failsafe.nft"
fi

echo "=== 6. Installerar systemd-enheter och polkit-regler ==="
cp "$SCRIPT_DIR"/systemd/*.service "$SCRIPT_DIR"/systemd/*.timer /etc/systemd/system/
cp "$SCRIPT_DIR"/systemd/*.rules /etc/polkit-1/rules.d/

# nf_tables tidigt, innan systemd-networkd startar. Utan detta loggar
# networkd "Failed to open nftables netlink socket ... Protocol not
# supported" och hoppar över IPMasquerade=/NFTSet=.
if [ -f "$SCRIPT_DIR/systemd/modules-load.d-security-harbor.conf" ]; then
  install -D -m 0644 "$SCRIPT_DIR/systemd/modules-load.d-security-harbor.conf" \
    /etc/modules-load.d/security-harbor.conf
else
  echo "VARNING: modules-load.d-security-harbor.conf saknas i paketet." >&2
fi

# Loggtak: journalen och Suricatas loggar.
#
# Mätt 2026-08-27 på en skarp installation: journalen 2 GB med
# SystemMaxUse=8G tillåtet, eve.json 1,47 GB, stats.log 393 MB, fast.log
# 77 MB — efter fyra dygns drift, på en 30 GB-disk. Distributionens
# logrotate-fil för Suricata saknar frekvensdirektiv och ärver global
# "weekly" med rotate 14, alltså fjorton veckors loggar.
if [ -f "$SCRIPT_DIR/systemd/journald-security-harbor.conf" ]; then
  install -D -m 0644 "$SCRIPT_DIR/systemd/journald-security-harbor.conf" \
    /etc/systemd/journald.conf.d/security-harbor.conf
  echo "-> journal-tak: SystemMaxUse=512M (drop-in)"
  # Verkställ direkt så att en redan uppsvälld journal krymper nu och inte
  # först vid nästa omstart.
  systemctl kill --kill-whom=main --signal=SIGUSR2 systemd-journald.service 2>/dev/null || true
fi

if [ -f "$SCRIPT_DIR/systemd/logrotate-suricata.conf" ] && [ -d /etc/logrotate.d ]; then
  if [ -f /etc/logrotate.d/suricata ] && [ ! -f /etc/logrotate.d/suricata.security-harbor-orig ]; then
    cp /etc/logrotate.d/suricata /etc/logrotate.d/suricata.security-harbor-orig
  fi
  install -m 0644 "$SCRIPT_DIR/systemd/logrotate-suricata.conf" /etc/logrotate.d/suricata
  echo "-> Suricata-loggar: daily + size 100M, rotate 5 (original sparat som .security-harbor-orig)"
  # Kontrollera att regeluppsättningen är giltig och kör en gång direkt, så
  # att befintliga jättefiler beskärs vid installation i stället för i natt.
  if command -v logrotate >/dev/null 2>&1; then
    if logrotate -d /etc/logrotate.d/suricata >/dev/null 2>&1; then
      logrotate /etc/logrotate.d/suricata 2>/dev/null || true
    else
      echo "VARNING: logrotate avvisade den nya Suricata-konfigurationen; återställer originalet." >&2
      [ -f /etc/logrotate.d/suricata.security-harbor-orig ] && \
        cp /etc/logrotate.d/suricata.security-harbor-orig /etc/logrotate.d/suricata
    fi
  fi
fi

# Suricata: minnestak skalat efter maskinens RAM.
#
# Memcaps i suricata.yaml lämnas medvetet orörda — uppmätt använder poolerna
# ~44 MB av ~528 MB tilldelat tak, så en sänkning frigör ingenting. Minnet
# ligger i detect-motorn (52 000+ regler) och den enda riktiga hävstången där
# är att minska regelsetet, vilket är ett säkerhetsbeslut installern inte ska
# fatta åt någon.
if [ -f "$SCRIPT_DIR/systemd/suricata-memory.conf.tmpl" ] && [ "$MODE" = "gateway" ]; then
  TOTAL_MB=$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo)
  # MJUKT tak: stryper och återvinner, dödar inte.
  #
  # Golvet 1024 MB är MÄTT, inte valt: med ET Open (~52 600 regler) ligger
  # Suricata på ~425 MB vid kall start, men en live-reload av regelsetet höjer
  # det stationära till ~650 MB och toppar på ~858 MB. Värdet planar ut där —
  # tre reload-cykler i rad gav 647/640/667 MB stationärt och 795/856/858 MB
  # topp, alltså ingen läcka. Ett MemoryHigh under ~900 MB hade strypt
  # Suricata vid varje daglig regeluppdatering.
  HIGH_MB=$(( TOTAL_MB * 30 / 100 ))
  [ "$HIGH_MB" -lt 1024 ] && HIGH_MB=1024
  [ "$HIGH_MB" -gt 1536 ] && HIGH_MB=1536

  # HÅRT tak sätts bara när maskinen har råd med det. En live-reload av
  # regelsetet håller två detect-motorer samtidigt (~2x stationärt, uppmätt
  # ~423 MB stationärt => ~850 MB topp). Ett hårt tak under den toppen hade
  # dödat Suricata vid varje daglig regeluppdatering, så på små maskiner
  # stryper vi bara.
  MAX_LINE="# MemoryMax utelamnat: $TOTAL_MB MB RAM racker inte for ett hart tak ovanfor"
  MAX_LINE="$MAX_LINE den uppmatta toppen (~858 MB) vid regel-reload."
  if [ "$TOTAL_MB" -ge 3000 ]; then
    MAX_MB=$(( TOTAL_MB * 45 / 100 ))
    [ "$MAX_MB" -lt 1536 ] && MAX_MB=1536
    [ "$MAX_MB" -gt 2560 ] && MAX_MB=2560
    MAX_LINE="MemoryMax=${MAX_MB}M"
    echo "-> Suricata minnestak: MemoryHigh=${HIGH_MB}M MemoryMax=${MAX_MB}M (RAM: ${TOTAL_MB} MB)"
  else
    echo "-> Suricata minnestak: MemoryHigh=${HIGH_MB}M, inget hårt tak (RAM: ${TOTAL_MB} MB)"
  fi

  install -d -m 0755 /etc/systemd/system/suricata.service.d
  sed -e "s|{{MEMORY_HIGH}}|${HIGH_MB}M|g" \
      -e "s|{{MEMORY_MAX_LINE}}|${MAX_LINE}|g" \
      "$SCRIPT_DIR/systemd/suricata-memory.conf.tmpl" \
      > /etc/systemd/system/suricata.service.d/security-harbor-memory.conf
fi

# systemd-networkd-wait-online: ta bort --dns. På en router som äger sin egen
# DNS är beroendet cirkulärt (Unbound konfigureras av agenten, som startar
# efter network-online.target). Mätt 2026-08-27 blockerade det
# network-online.target i 2 min 0,9 s, vilket i sin tur gjorde Suricata blind
# de första 2 min 21 s efter boot.
WAIT_ONLINE_BIN=""
for _cand in /usr/lib/systemd/systemd-networkd-wait-online \
             /lib/systemd/systemd-networkd-wait-online; do
  [ -x "$_cand" ] && { WAIT_ONLINE_BIN="$_cand"; break; }
done
if [ -n "$WAIT_ONLINE_BIN" ] && [ -f "$SCRIPT_DIR/systemd/wait-online-no-dns.conf.tmpl" ]; then
  echo "-> systemd-networkd-wait-online: $WAIT_ONLINE_BIN (--any --timeout=30, utan --dns)"
  install -d -m 0755 /etc/systemd/system/systemd-networkd-wait-online.service.d
  sed "s|{{WAIT_ONLINE_BIN}}|$WAIT_ONLINE_BIN|g" \
    "$SCRIPT_DIR/systemd/wait-online-no-dns.conf.tmpl" \
    > /etc/systemd/system/systemd-networkd-wait-online.service.d/security-harbor.conf
else
  echo "VARNING: hoppar över wait-online-drop-in (binären eller mallen saknas)." >&2
  echo "         Suricata kan då starta flera minuter efter boot." >&2
fi
if [ "$MODE" = "host" ] && ! grep -q -- '--mode=host' /etc/systemd/system/security-harbor-agent.service; then
  # --mode styr bara SEEDNINGEN av en helt ny installation (se
  # store.NewStore) - ofarligt att lämna kvar på ExecStart permanent,
  # ignoreras efter första uppstarten. grep-vakten ovan gör detta
  # idempotent (annars skulle en omkörning stapla på flaggan flera gånger).
  sed -i 's|^ExecStart=/usr/local/bin/security-harbor-agent .*|& --mode=host|' \
    /etc/systemd/system/security-harbor-agent.service
fi
systemctl daemon-reload

echo "=== 7. Startar (eller startar OM) tjänster ==="
# `enable --now` startar bara en tjänst som INTE redan kör — vid en
# OMinstallation/uppdatering ligger den gamla processen kvar med den gamla
# binären i minnet (upptäckt 2026-08-23: en ny binär installerades men
# 0.16.0-processen fortsatte köra med den hårdkodade 10.0.0.163-bindningen).
# Använd därför enable + restart så att den nya binären och de nya
# konfig-/failsafe-filerna faktiskt laddas.
# Failsafe-enheten flyttades från WantedBy=multi-user.target till
# WantedBy=network-pre.target (annars var den inte schemalagd förrän
# gränssnitten redan var uppe — 2,75 s utan regeluppsättning, mätt
# 2026-08-27). Ett blott `enable` skapar den nya symlänken men lämnar den
# gamla kvar under multi-user.target.wants, så disable först.
systemctl disable security-harbor-failsafe.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/multi-user.target.wants/security-harbor-failsafe.service
systemctl enable security-harbor-failsafe.service
systemctl restart security-harbor-failsafe.service
systemctl enable security-harbor-agent.service
systemctl restart security-harbor-agent.service
if [ "$MODE" = "gateway" ]; then
  systemctl enable --now security-harbor-suricata-update.timer
  echo "=== 8. Hämtar initialt Suricata-regelset (ET Open) ==="
  if ! suricata-update; then
    echo "VARNING: suricata-update misslyckades (t.ex. inget nätverk just nu)." >&2
    echo "Kör 'sudo suricata-update' manuellt senare, eller vänta på nästa schemalagda körning." >&2
  fi
fi

echo ""
echo "=== Installation klar (läge: $MODE) ==="
if [ "$MODE" = "host" ]; then
  echo "Management-gränssnitt: https://<den här datorns IP>:8443"
else
  echo "Management-gränssnitt: https://<brandväggens LAN-IP>:8443"
  echo "(en brandvägg har flera nätverkskort - kontrollera 'ip -4 addr' för att"
  echo " se vilket som är LAN-sidan innan du ansluter)"
fi
echo "Standard-inloggning:   master / SecurityHarbor2026!"
echo ""
echo "*** BYT LÖSENORDET DIREKT via GUI:t (Settings) - standardlösenordet"
echo "*** är dokumenterat i källkoden och ska ALDRIG lämnas kvar i drift."
