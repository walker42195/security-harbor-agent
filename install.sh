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
LAN_DEVICE=""
HOST_DEVICE=""
SKIP_PACKAGES=0
for arg in "$@"; do
  case "$arg" in
    --mode=*) MODE="${arg#*=}" ;;
    --wan-device=*) WAN_DEVICE="${arg#*=}" ;;
    --lan-device=*) LAN_DEVICE="${arg#*=}" ;;
    --host-device=*) HOST_DEVICE="${arg#*=}" ;;
    --skip-packages) SKIP_PACKAGES=1 ;;
    -h|--help)
      echo "Användning: $0 [--mode=gateway|host] [kortval] [--skip-packages]"
      echo "  --mode           Hoppa över den interaktiva frågan om driftläge."
      echo "  --wan-device     (gateway) Kortet mot internet. Frågas annars."
      echo "  --lan-device     (gateway) Kortet mot det interna nätet. Frågas annars."
      echo "  --host-device    (host) Maskinens nätverkskort. Frågas annars, och"
      echo "                   väljs automatiskt om maskinen bara har ett."
      echo "  --skip-packages  Installera inga systempaket (för distributioner"
      echo "                   installern inte kan paketnamnen för - installera"
      echo "                   motsvarigheterna för hand först)."
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

# --- Distro-detektering -------------------------------------------------
#
# Installern var ursprungligen hårdkodad mot apt-get + Debians paketnamn.
# Upptäckt 2026-08-30 vid ett test på Arch: `pacman -S` avbröt med "target
# not found" på bind9-dnsutils/rsyslog/polkitd, och eftersom skriptet kör
# med `set -e` dog HELA installationen mitt i steg 1 — ingen binär, ingen
# systemd-enhet, inget TLS-certifikat. Appen visade då "Kunde inte
# kontrollera certifikatet", vilket i själva verket var ett connection
# refused mot en agent som aldrig installerats.
#
# ID_LIKE fångar derivat (Linux Mint => debian, EndeavourOS/Manjaro => arch)
# utan att varje enskild distro behöver listas.
DISTRO_ID="$(. /etc/os-release 2>/dev/null && echo "$ID")"
DISTRO_LIKE="$(. /etc/os-release 2>/dev/null && echo "$ID_LIKE")"
PKG_FAMILY=""
case " $DISTRO_ID $DISTRO_LIKE " in
  *" debian "*|*" ubuntu "*) PKG_FAMILY="debian" ;;
  *" arch "*)                PKG_FAMILY="arch" ;;
esac
if [ -z "$PKG_FAMILY" ]; then
  echo "Okänd distribution: ID=${DISTRO_ID:-?} ID_LIKE=${DISTRO_LIKE:-?}" >&2
  echo "Installern kan paketnamn för Debian/Ubuntu och Arch. Installera" >&2
  echo "motsvarande paket för hand och kör om med --skip-packages." >&2
  [ "$SKIP_PACKAGES" = "1" ] || exit 1
fi
echo "-> Distribution: ${DISTRO_ID:-okänd} (paketfamilj: ${PKG_FAMILY:-ingen})"

pkg_refresh() {
  case "$PKG_FAMILY" in
    debian) apt-get update -qq ;;
    # Arch stödjer inte partiella uppgraderingar: `pacman -Sy paket` mot en
    # gammal lokal databas kan dra in ett paket byggt mot nyare bibliotek än
    # de installerade och lämna systemet trasigt. -Syu är därför inte ett
    # val installern gör av bekvämlighet utan det enda säkra sättet att
    # installera ett paket på Arch.
    arch)   pacman -Syu --noconfirm ;;
  esac
}
pkg_available() {
  case "$PKG_FAMILY" in
    debian) apt-cache show "$1" >/dev/null 2>&1 ;;
    arch)   pacman -Si "$1" >/dev/null 2>&1 ;;
  esac
}
pkg_installed() {
  case "$PKG_FAMILY" in
    debian) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'ok installed' ;;
    arch)   pacman -Qi "$1" >/dev/null 2>&1 ;;
  esac
}
pkg_install() {
  case "$PKG_FAMILY" in
    debian) apt-get install -y "$@" ;;
    arch)   pacman -S --needed --noconfirm "$@" ;;
  esac
}

# --- Paketnamn per familj -----------------------------------------------
#
# REQUIRED = utan dessa fungerar inte agenten alls; misslyckas de avbryts
# installationen. OPTIONAL = funktioner som degraderar snyggt när paketet
# saknas (syslog-vidarebefordran och IDS) — de får INTE fälla installationen,
# vilket är precis vad som hände på Arch där varken rsyslog eller suricata
# finns i de officiella repona (båda ligger i AUR).
case "$PKG_FAMILY" in
  debian)
    export DEBIAN_FRONTEND=noninteractive
    REQ_COMMON="nftables tcpdump nmap bind9-dnsutils polkitd jq"
    REQ_GATEWAY="chrony kea-dhcp4-server unbound wireguard-tools openvpn haproxy"
    # suricata-update är ett eget paket på Debian; på Arch ingår verktyget
    # i suricata-paketet, därav skillnaden i listan nedan.
    OPT_COMMON="rsyslog"
    OPT_GATEWAY="suricata suricata-update"
    ;;
  arch)
    REQ_COMMON="nftables tcpdump nmap bind polkit jq"
    REQ_GATEWAY="chrony kea unbound wireguard-tools openvpn haproxy"
    OPT_COMMON="rsyslog"
    OPT_GATEWAY="suricata"
    ;;
esac

if [ "$MODE" = "host" ]; then
  # Enkelkorts-/värddator-läge (Fas 13): ingen DHCP-server, ingen
  # rekursiv DNS-resolver, ingen VPN-server, ingen IDS - det här skyddar
  # EN dator, det kör inte en gateway-roll åt andra.
  REQUIRED_PKGS="$REQ_COMMON"
  OPTIONAL_PKGS="$OPT_COMMON"
else
  REQUIRED_PKGS="$REQ_COMMON $REQ_GATEWAY"
  OPTIONAL_PKGS="$OPT_COMMON $OPT_GATEWAY"
fi

SKIPPED_PKGS=""
if [ "$SKIP_PACKAGES" = "1" ]; then
  echo "-> --skip-packages angivet: hoppar över paketinstallationen helt."
else
  pkg_refresh
  # shellcheck disable=SC2086 -- listorna är avsiktligt ordseparerade
  pkg_install $REQUIRED_PKGS

  for p in $OPTIONAL_PKGS; do
    if pkg_installed "$p"; then
      continue
    fi
    if pkg_available "$p"; then
      if ! pkg_install "$p"; then
        echo "VARNING: kunde inte installera valfritt paket '$p' - fortsätter." >&2
        SKIPPED_PKGS="$SKIPPED_PKGS $p"
      fi
    else
      echo "-> Valfritt paket '$p' finns inte i ${DISTRO_ID}s paketrepon - hoppar över."
      SKIPPED_PKGS="$SKIPPED_PKGS $p"
    fi
  done
fi

# Vilka VALFRIA funktioner som faktiskt är tillgängliga avgörs av vad som
# finns på disk efteråt - inte av om paketinstallationen gick bra. Då
# fungerar det också när paketet redan installerats för hand (t.ex. via AUR
# på Arch) eller när --skip-packages använts.
HAVE_RSYSLOG=0
HAVE_SURICATA=0
command -v rsyslogd >/dev/null 2>&1 && HAVE_RSYSLOG=1
command -v suricata >/dev/null 2>&1 && HAVE_SURICATA=1

if [ "$MODE" = "gateway" ] && [ "$PKG_FAMILY" != "debian" ]; then
  echo "VARNING: gateway-läge är i dagsläget bara verifierat på Debian/Ubuntu." >&2
  echo "         Tjänstenamnen för Kea/Unbound/OpenVPN skiljer sig mellan" >&2
  echo "         distributioner (t.ex. kea-dhcp4-server.service på Debian mot" >&2
  echo "         kea-dhcp4.service på Arch) och agenten använder Debians namn." >&2
fi

echo "=== 2. Skapar systemanvändare/grupp 'security-harbor' ==="
if ! getent group security-harbor >/dev/null; then
  groupadd --system security-harbor
fi
if ! id -u security-harbor >/dev/null 2>&1; then
  # nologin ligger i /usr/sbin på Debian och i /usr/bin på Arch (där
  # /usr/sbin visserligen är en symlänk till /usr/bin, men det gäller inte
  # alla distributioner) - leta upp den i stället för att gissa.
  NOLOGIN=""
  for _c in /usr/sbin/nologin /usr/bin/nologin /sbin/nologin; do
    [ -x "$_c" ] && { NOLOGIN="$_c"; break; }
  done
  useradd --system --no-create-home --shell "${NOLOGIN:-/bin/false}" \
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
# Bara när rsyslog faktiskt är installerat - syslog-vidarebefordran är en
# VALFRI funktion och saknas t.ex. helt i Arch officiella repon.
if [ "$HAVE_RSYSLOG" = "1" ] && [ -d /etc/rsyslog.d ]; then
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
# /etc/chrony/conf.d på Debian, /etc/chrony.d på Arch - loopen hoppar över
# den som inte finns.
for d in /etc/kea /etc/unbound /etc/unbound/unbound.conf.d /etc/openvpn \
         /etc/wireguard /etc/chrony/conf.d /etc/chrony.d; do
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

echo "=== 5. Väljer nätverkskort ==="
#
# Kortvalet styr TVÅ saker som båda måste peka på samma fysiska kort:
#   1) failsafe-regelsetet (WAN-sidan, gateway-läge)
#   2) agentens seed-config, via --wan-device/--lan-device/--host-device
#      på ExecStart nedan
#
# Fram till 2026-08-30 frågade installern bara efter WAN-kortet, och bara i
# gateway-läge — seed-configen hade korten HÅRDKODADE ("eth0" i host-läge,
# "ens18"/"ens19" i gateway-läge). Policyerna som släpper in SSH och
# Management-API:t matchar på kortets namn via zonen, så på en maskin med
# andra namn matchade de ingenting och maskinen låste ute sig själv så fort
# agenten applicerade sin första config.

# Bara FYSISKA kort. /sys/class/net/<namn>/device är symlänken till den
# underliggande PCI-/USB-enheten och saknas för bryggor, veth, docker0,
# tun/tap och wireguard - inget av dem är ett giltigt val här.
list_physical_nics() {
  for _n in $(ls /sys/class/net 2>/dev/null); do
    [ "$_n" = "lo" ] && continue
    [ -e "/sys/class/net/$_n/device" ] || continue
    echo "$_n"
  done
}

NICS="$(list_physical_nics)"
NIC_COUNT="$(echo "$NICS" | grep -c .)"
DEFAULT_NIC="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") {print $(i+1); exit}}')"

if [ "$NIC_COUNT" -eq 0 ]; then
  echo "FEL: hittade inga fysiska nätverkskort. Brandväggen kan inte" >&2
  echo "     konfigureras utan minst ett kort." >&2
  exit 1
fi

# Skriver ut korten numrerade, med IP och länkstatus. Ett kort utan
# inkopplad sladd syns som "down"/utan IP - praktiskt när man installerar
# innan WAN kopplas in. Kortet med default-rutten märks ut eftersom det per
# definition är det man administrerar maskinen över just nu.
print_nic_list() {
  echo ""
  echo "Nätverkskort på den här maskinen:"
  _i=0
  for _n in $NICS; do
    _i=$((_i + 1))
    _ip="$(ip -4 -o addr show dev "$_n" 2>/dev/null | awk '{print $4}' | paste -sd', ' -)"
    _state="$(cat "/sys/class/net/$_n/operstate" 2>/dev/null || echo '?')"
    _mark=""
    [ "$_n" = "$DEFAULT_NIC" ] && _mark="  <- du är ansluten hit nu (default-rutt)"
    printf "  [%d] %-12s %-20s [%s]%s\n" "$_i" "$_n" "${_ip:-(ingen IP)}" "$_state" "$_mark"
  done
  echo ""
}

# nic_by_index <nummer> - översätter ett listnummer till kortnamn. Tomt om
# numret är utanför listan.
nic_by_index() {
  echo "$NICS" | sed -n "$1p"
}

# ask_nic <fråga> <förvalt kort> [kort att utesluta]
# Svaret får vara antingen ett listnummer eller ett kortnamn. Sätter ASK_NIC.
ask_nic() {
  _prompt="$1"
  _default="$2"
  _exclude="$3"
  if [ ! -r /dev/tty ]; then
    echo "Ingen terminal tillgänglig - använder $_default" >&2
    ASK_NIC="$_default"
    return
  fi
  while :; do
    read -r -p "$_prompt [${_default}]: " _ans </dev/tty
    _ans="${_ans:-$_default}"
    # Ett rent siffersvar tolkas som listnummer.
    case "$_ans" in
      ''|*[!0-9]*) : ;;
      *) _byidx="$(nic_by_index "$_ans")"; [ -n "$_byidx" ] && _ans="$_byidx" ;;
    esac
    if ! echo "$NICS" | grep -qx "$_ans"; then
      echo "  '$_ans' är inget av maskinens nätverkskort. Försök igen." >&2
      continue
    fi
    if [ -n "$_exclude" ] && [ "$_ans" = "$_exclude" ]; then
      echo "  '$_ans' är redan valt som WAN - WAN och LAN måste vara olika kort." >&2
      continue
    fi
    ASK_NIC="$_ans"
    return
  done
}

if [ "$MODE" = "host" ]; then
  if [ -z "$HOST_DEVICE" ]; then
    if [ "$NIC_COUNT" -eq 1 ]; then
      HOST_DEVICE="$NICS"
      echo "-> Enda nätverkskortet: $HOST_DEVICE"
    else
      print_nic_list
      echo "Host-läge skyddar EN dator. Välj det kort brandväggen ska gälla för"
      echo "- normalt det du administrerar maskinen över."
      ask_nic "Nätverkskort" "${DEFAULT_NIC:-$(nic_by_index 1)}"
      HOST_DEVICE="$ASK_NIC"
    fi
  fi
  if ! echo "$NICS" | grep -qx "$HOST_DEVICE"; then
    echo "FEL: '$HOST_DEVICE' är inget fysiskt nätverkskort på den här maskinen." >&2
    echo "     Tillgängliga: $(echo "$NICS" | paste -sd', ' -)" >&2
    exit 1
  fi
  echo "-> Brandväggen gäller kortet: $HOST_DEVICE"
  cp "$SCRIPT_DIR/systemd/security-harbor-failsafe-host.nft.tmpl" "$CONF_DIR/security-harbor-failsafe.nft"
else
  if [ "$NIC_COUNT" -lt 2 ] && { [ -z "$WAN_DEVICE" ] || [ -z "$LAN_DEVICE" ]; }; then
    echo "FEL: gateway-läge kräver minst två nätverkskort (WAN och LAN), hittade" >&2
    echo "     $NIC_COUNT: $(echo "$NICS" | paste -sd', ' -)" >&2
    echo "     Kör om med --mode=host för att bara skydda den här datorn." >&2
    exit 1
  fi
  if [ -z "$WAN_DEVICE" ] || [ -z "$LAN_DEVICE" ]; then
    print_nic_list
    echo "WAN = kortet mot internet/utsidan."
    echo "LAN = det interna nätet, och det du administrerar brandväggen genom."
    if [ -n "$DEFAULT_NIC" ]; then
      echo ""
      echo "OBS: du är ansluten via $DEFAULT_NIC just nu. Väljer du det som WAN"
      echo "     tappar du åtkomsten till brandväggen så fort den startar."
    fi
  fi
  if [ -z "$WAN_DEVICE" ]; then
    ask_nic "WAN-kort (mot internet)" "$(nic_by_index 1)"
    WAN_DEVICE="$ASK_NIC"
  fi
  if [ -z "$LAN_DEVICE" ]; then
    # Förval: det kort som INTE är WAN. Med exakt två kort är det entydigt.
    _lan_default=""
    for _n in $NICS; do
      [ "$_n" = "$WAN_DEVICE" ] && continue
      _lan_default="$_n"
      break
    done
    [ -n "$DEFAULT_NIC" ] && [ "$DEFAULT_NIC" != "$WAN_DEVICE" ] && _lan_default="$DEFAULT_NIC"
    ask_nic "LAN-kort (internt nät)" "$_lan_default" "$WAN_DEVICE"
    LAN_DEVICE="$ASK_NIC"
  fi
  for _pair in "WAN:$WAN_DEVICE" "LAN:$LAN_DEVICE"; do
    _role="${_pair%%:*}"; _dev="${_pair#*:}"
    if ! echo "$NICS" | grep -qx "$_dev"; then
      echo "FEL: $_role-kortet '$_dev' finns inte på den här maskinen." >&2
      echo "     Tillgängliga: $(echo "$NICS" | paste -sd', ' -)" >&2
      exit 1
    fi
  done
  if [ "$WAN_DEVICE" = "$LAN_DEVICE" ]; then
    echo "FEL: WAN och LAN kan inte vara samma kort ($WAN_DEVICE)." >&2
    exit 1
  fi
  echo "-> WAN: $WAN_DEVICE"
  echo "-> LAN: $LAN_DEVICE"
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
  systemctl restart systemd-journald.service 2>/dev/null || true
  # Verkställ direkt. En omstart av journald läser in taket men BESKÄR inte
  # en redan uppsvälld journal — retentionen tillämpas först när nya filer
  # roteras. journalctl --vacuum-size gör det nu i stället för om flera dygn.
  journalctl --vacuum-size=512M >/dev/null 2>&1 || true
  journalctl --vacuum-time=2weeks >/dev/null 2>&1 || true
fi

if [ "$HAVE_SURICATA" = "1" ] && [ -f "$SCRIPT_DIR/systemd/logrotate-suricata.conf" ] && [ -d /etc/logrotate.d ]; then
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
if [ "$HAVE_SURICATA" = "1" ] && [ -f "$SCRIPT_DIR/systemd/suricata-memory.conf.tmpl" ] && [ "$MODE" = "gateway" ]; then
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
# SupplementaryGroups: filtrera bort grupper som inte finns på maskinen.
# systemd är kompromisslös här - en enda okänd grupp gör att enheten inte
# ens startar (status 216/GROUP, "Failed to determine supplementary groups"),
# den hoppar inte över den. `_kea` skapas av Debians kea-dhcp4-server-paket
# och finns inte alls på Arch, och inte heller i host-läge på Debian där Kea
# aldrig installeras. Upptäckt 2026-08-30: agenten restartloopade oändligt på
# en Arch-installation, utan att något i loggen pekade ut _kea som orsaken.
AGENT_UNIT=/etc/systemd/system/security-harbor-agent.service
SUPP_LINE="$(grep -m1 '^SupplementaryGroups=' "$AGENT_UNIT" 2>/dev/null || true)"
if [ -n "$SUPP_LINE" ]; then
  KEEP=""
  DROPPED=""
  for g in ${SUPP_LINE#SupplementaryGroups=}; do
    if getent group "$g" >/dev/null 2>&1; then
      KEEP="$KEEP $g"
    else
      DROPPED="$DROPPED $g"
    fi
  done
  KEEP="${KEEP# }"
  if [ -n "$DROPPED" ]; then
    echo "-> Hoppar över okända grupper i SupplementaryGroups:$DROPPED"
  fi
  if [ -n "$KEEP" ]; then
    sed -i "s|^SupplementaryGroups=.*|SupplementaryGroups=$KEEP|" "$AGENT_UNIT"
  else
    sed -i "s|^SupplementaryGroups=.*|# SupplementaryGroups: ingen av grupperna finns på den här maskinen|" "$AGENT_UNIT"
  fi
fi

# Seed-flaggor på ExecStart: driftläge och de valda korten. De styr BARA
# seedningen av en helt ny installation (se store.NewStore/SeedOptions) och
# ignoreras när running.json redan finns - ofarliga att lämna kvar permanent.
#
# Enheten kopieras om från paketet vid varje installation, så raden byggs
# alltid från grunden i stället för att lägga till flaggor på en befintlig.
# Den tidigare varianten la på "--mode=host" med en grep-vakt; med fyra
# flaggor blir det både ordkänsligt och lätt att stapla dubbletter.
SEED_ARGS=""
if [ "$MODE" = "host" ]; then
  SEED_ARGS="--mode=host"
  [ -n "$HOST_DEVICE" ] && SEED_ARGS="$SEED_ARGS --host-device=$HOST_DEVICE"
else
  [ -n "$WAN_DEVICE" ] && SEED_ARGS="$SEED_ARGS --wan-device=$WAN_DEVICE"
  [ -n "$LAN_DEVICE" ] && SEED_ARGS="$SEED_ARGS --lan-device=$LAN_DEVICE"
fi
SEED_ARGS="${SEED_ARGS# }"
if [ -n "$SEED_ARGS" ]; then
  echo "-> Seed-argument till agenten: $SEED_ARGS"
  sed -i "s|^ExecStart=/usr/local/bin/security-harbor-agent .*|ExecStart=/usr/local/bin/security-harbor-agent --data-dir $DATA_DIR $SEED_ARGS|" \
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

# nf_tables måste vara laddad INNAN failsafe-enheten kör `nft -f`.
# /etc/modules-load.d-filen ovan gäller först vid nästa boot, och till
# skillnad från Debians nftables-paket laddar Arch-paketet ingen modul vid
# installation. Utan detta dog failsafe med "Unable to initialize Netlink
# socket: Protocol not supported" (upptäckt 2026-08-30 på Arch).
if ! modprobe nf_tables 2>/dev/null; then
  # Vanligaste orsaken på ett rullande system: kärnan har uppgraderats men
  # maskinen har inte startats om, så /lib/modules för den KÖRANDE kärnan är
  # borttagen och INGEN modul går att ladda. Felet har inget med Security
  # Harbor att göra, men utan den här kontrollen syns det bara som ett
  # obegripligt "Protocol not supported" från nft.
  if [ ! -d "/lib/modules/$(uname -r)" ]; then
    echo "" >&2
    echo "FEL: /lib/modules/$(uname -r) saknas - kärnan har uppgraderats men" >&2
    echo "     maskinen har inte startats om. Inga kärnmoduler (inklusive" >&2
    echo "     nf_tables) går att ladda förrän du startat om." >&2
    echo "" >&2
    echo "     Starta om maskinen och kör installern igen." >&2
    exit 1
  fi
  if ! grep -q nf_tables /proc/modules 2>/dev/null && [ ! -d /proc/sys/net/netfilter ]; then
    echo "FEL: kunde inte ladda kärnmodulen nf_tables - brandväggen kan inte" >&2
    echo "     sätta några regler på den här kärnan." >&2
    exit 1
  fi
fi
systemctl restart security-harbor-failsafe.service
systemctl enable security-harbor-agent.service
systemctl restart security-harbor-agent.service
if [ "$MODE" = "gateway" ] && [ "$HAVE_SURICATA" = "1" ]; then
  systemctl enable --now security-harbor-suricata-update.timer
  echo "=== 8. Hämtar initialt Suricata-regelset (ET Open) ==="
  if command -v suricata-update >/dev/null 2>&1; then
    if ! suricata-update; then
      echo "VARNING: suricata-update misslyckades (t.ex. inget nätverk just nu)." >&2
      echo "Kör 'sudo suricata-update' manuellt senare, eller vänta på nästa schemalagda körning." >&2
    fi
  else
    echo "VARNING: suricata är installerat men suricata-update saknas - IDS startar utan regelset." >&2
  fi
fi

echo ""
echo "=== Installation klar (läge: $MODE) ==="

# Valfria funktioner som INTE är tillgängliga på den här maskinen. Skrivs ut
# sist så det är det sista man ser - annars är det lätt att missa varför
# IDS-reglaget i GUI:t inte går att slå på.
if [ "$HAVE_RSYSLOG" != "1" ] || { [ "$MODE" = "gateway" ] && [ "$HAVE_SURICATA" != "1" ]; }; then
  echo ""
  echo "Valfria funktioner som inte är tillgängliga här:"
  if [ "$HAVE_RSYSLOG" != "1" ]; then
    echo "  - Syslog-vidarebefordran (kräver rsyslog). All lokal loggning sker"
    echo "    ändå i journald som vanligt; det som saknas är möjligheten att"
    echo "    skicka loggarna vidare till en central syslog-mottagare."
    [ "$PKG_FAMILY" = "arch" ] && \
      echo "    På Arch: 'yay -S rsyslog' (AUR) och kör om installern."
  fi
  if [ "$MODE" = "gateway" ] && [ "$HAVE_SURICATA" != "1" ]; then
    echo "  - IDS (kräver suricata + suricata-update)."
    [ "$PKG_FAMILY" = "arch" ] && \
      echo "    På Arch: 'yay -S suricata' (AUR) och kör om installern."
  fi
fi
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
