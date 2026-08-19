#!/bin/bash
# Security Harbor Agent - installer.
#
# Körs från en uppackad installationsbunt (byggd med ./build_release.sh,
# se dist/) på en FÄRDIG Ubuntu/Debian-maskin. Laddar INTE ner något från
# nätet självt (ingen OTA/auto-update-funktion finns i det här steget) -
# binärerna och systemd-filerna måste redan ligga bredvid det här
# skriptet. Idempotent: kan köras om på en redan installerad maskin utan
# att förstöra något (paket/användare/kataloger skapas bara om de saknas).
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "Måste köras som root (sudo ./install.sh)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="/var/lib/security-harbor"
CONF_DIR="/etc/security-harbor"
BIN_DIR="/usr/local/bin"

for bin in security-harbor-agent security-harbor-nmap-runner security-harbor-tcpdump-runner; do
  if [ ! -f "$SCRIPT_DIR/$bin" ]; then
    echo "Hittar inte $SCRIPT_DIR/$bin - kör detta skript från en bunt byggd med build_release.sh" >&2
    exit 1
  fi
done

echo "=== 1. Installerar systempaket ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y \
  nftables \
  kea-dhcp4-server \
  unbound \
  wireguard-tools \
  openvpn \
  tcpdump \
  suricata \
  suricata-update \
  rsyslog \
  polkitd

echo "=== 2. Skapar systemanvändare/grupp 'security-harbor' ==="
if ! getent group security-harbor >/dev/null; then
  groupadd --system security-harbor
fi
if ! id -u security-harbor >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin \
    --gid security-harbor security-harbor
fi
# _kea-gruppen skapas av kea-dhcp4-server-paketet ovan - krävs för att
# läsa DHCP-lease-databasen (DNS.DHCPHostnameRegistration).
if getent group _kea >/dev/null; then
  usermod -a -G _kea security-harbor
fi

echo "=== 3. Skapar kataloger ==="
mkdir -p "$DATA_DIR" "$CONF_DIR"
chown -R security-harbor:security-harbor "$DATA_DIR" "$CONF_DIR"
chmod 700 "$DATA_DIR"

echo "=== 4. Installerar binärer ==="
for bin in security-harbor-agent security-harbor-nmap-runner security-harbor-tcpdump-runner; do
  install -m 0755 -o root -g root "$SCRIPT_DIR/$bin" "$BIN_DIR/$bin"
done

echo "=== 5. Installerar systemd-enheter och polkit-regler ==="
cp "$SCRIPT_DIR"/systemd/*.service "$SCRIPT_DIR"/systemd/*.timer /etc/systemd/system/
cp "$SCRIPT_DIR"/systemd/*.rules /etc/polkit-1/rules.d/
systemctl daemon-reload

echo "=== 6. Startar tjänster ==="
systemctl enable --now security-harbor-agent.service
systemctl enable --now security-harbor-suricata-update.timer

echo "=== 7. Hämtar initialt Suricata-regelset (ET Open) ==="
if ! suricata-update; then
  echo "VARNING: suricata-update misslyckades (t.ex. inget nätverk just nu)." >&2
  echo "Kör 'sudo suricata-update' manuellt senare, eller vänta på nästa schemalagda körning." >&2
fi

echo ""
echo "=== Installation klar ==="
echo "Management-gränssnitt: https://<brandväggens LAN-IP>:8443"
echo "(en brandvägg har flera nätverkskort - kontrollera 'ip -4 addr' för att"
echo " se vilket som är LAN-sidan innan du ansluter)"
echo "Standard-inloggning:   master / SecurityHarbor2026!"
echo ""
echo "*** BYT LÖSENORDET DIREKT via GUI:t (Settings) - standardlösenordet"
echo "*** är dokumenterat i källkoden och ska ALDRIG lämnas kvar i drift."
