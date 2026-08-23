#!/bin/bash
# Security Harbor Agent - avinstallerare (Fas 13).
#
# Stoppar och tar bort agenten, hjälptjänsterna, systemd-enheterna och
# polkit-reglerna. Config/nycklar och de systempaket install.sh
# installerade lämnas KVAR som standard (--purge tar bort dem också).
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "Måste köras som root (sudo ./uninstall.sh)" >&2
  exit 1
fi

DATA_DIR="/var/lib/security-harbor"
CONF_DIR="/etc/security-harbor"
BIN_DIR="/usr/local/bin"

PURGE=false
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=true ;;
    -h|--help)
      echo "Användning: $0 [--purge]"
      echo "  --purge  Ta även bort $DATA_DIR (all config/nycklar), $CONF_DIR,"
      echo "           security-harbor-systemkontot och de systempaket install.sh"
      echo "           installerade. Kan INTE ångras utan en sparad backup."
      exit 0
      ;;
  esac
done

echo "=== 1. Stoppar och inaktiverar tjänster ==="
for unit in \
  security-harbor-agent.service \
  security-harbor-failsafe.service \
  security-harbor-suricata-update.timer \
  security-harbor-suricata-update.service \
  security-harbor-nmap.service \
  security-harbor-tcpdump.service \
  security-harbor-update.service
do
  systemctl disable --now "$unit" 2>/dev/null || true
done

echo "=== 2. Tar bort systemd-enheter och polkit-regler ==="
rm -f /etc/systemd/system/security-harbor-*.service
rm -f /etc/systemd/system/security-harbor-*.timer
rm -f /etc/polkit-1/rules.d/10-security-harbor-*.rules
systemctl daemon-reload

echo "=== 3. Tar bort binärer och självuppdaterings-runnern ==="
rm -f "$BIN_DIR/security-harbor-agent" \
      "$BIN_DIR/security-harbor-nmap-runner" \
      "$BIN_DIR/security-harbor-tcpdump-runner"
# Självuppdaterings-runnern (installerad av install.sh, se
# systemd/update-runner.sh) och dess katalog.
rm -rf /usr/local/lib/security-harbor

if [ "$PURGE" = true ]; then
  echo "=== 4. --purge: tar bort config/nycklar, systemkonto och paket ==="
  echo "VARNING: Detta raderar $DATA_DIR (all config, nycklar, användarkonton)"
  echo "permanent. Har du en sparad backup om du ångrar dig?"
  if [ -r /dev/tty ]; then
    read -r -p "Skriv 'ja' för att bekräfta: " CONFIRM </dev/tty
    if [ "$CONFIRM" != "ja" ]; then
      echo "Avbryter --purge (resten av avinstallationen är redan klar)." >&2
      exit 0
    fi
  fi
  rm -rf "$DATA_DIR" "$CONF_DIR"
  if id -u security-harbor >/dev/null 2>&1; then
    userdel security-harbor 2>/dev/null || true
  fi
  if getent group security-harbor >/dev/null; then
    groupdel security-harbor 2>/dev/null || true
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get remove -y \
    kea-dhcp4-server unbound wireguard-tools openvpn \
    suricata suricata-update 2>/dev/null || true
  echo "-> Paket borttagna (nftables/tcpdump/rsyslog/polkitd lämnas kvar - de"
  echo "   är vanliga systemverktyg som annan mjukvara kan bero på)."
else
  echo "=== 4. Config/nycklar i $DATA_DIR lämnas KVAR (kör med --purge för att ta bort) ==="
fi

echo ""
echo "=== Avinstallation klar ==="
