#!/bin/bash
# Security Harbor - privilegierad självuppdaterings-installer.
#
# Körs som root av security-harbor-update.service (oneshot), som i sin tur
# triggas av den oprivilegierade agenten via `systemctl start --no-block`.
# Installerar en NEDLADDAD OCH VERIFIERAD bunt som agenten stagat i
# STAGING_DIR. Om-verifierar Ed25519-signaturen som root via den REDAN
# INSTALLERADE (betrodda) agent-binären innan något packas upp - den nya,
# ännu overifierade binären i bunten får aldrig verifiera sig själv.
set -euo pipefail

STAGING_DIR="/var/lib/security-harbor/updates"
TARBALL="$STAGING_DIR/security-harbor-dist.tar.gz"
SIG="$STAGING_DIR/security-harbor-dist.tar.gz.sig"
AGENT_BIN="/usr/local/bin/security-harbor-agent"

log() { echo "[sh-update] $*"; }

# Ömsesidig uteslutning mot en samtidig security-harbor-rollback@.service (se
# samma spärr och motivering där) - icke-blockerande, vägrar starta hellre än
# att riskera en halvfärdig filkopiering.
LOCK_FILE="$STAGING_DIR/.install.lock"
mkdir -p "$STAGING_DIR"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log "en annan uppdatering/rollback pågår redan - avbryter."
    exit 1
fi

if [[ ! -f "$TARBALL" || ! -f "$SIG" ]]; then
    log "ingen stagad bunt att installera ($TARBALL) - avbryter."
    exit 1
fi

log "verifierar signatur som root via den installerade agenten..."
if ! "$AGENT_BIN" --verify-update "$TARBALL" --verify-sig "$SIG"; then
    log "SIGNATURVERIFIERING MISSLYCKADES - installerar INTE. Tar bort den stagade bunten."
    rm -f "$TARBALL" "$SIG" "$STAGING_DIR/staged-version.txt"
    exit 1
fi
log "signatur OK."

WORK="$(mktemp -d /tmp/sh-update.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

log "packar upp bunten..."
tar -xzf "$TARBALL" -C "$WORK"

if [[ ! -x "$WORK/install.sh" ]]; then
    log "bunten saknar körbar install.sh - avbryter."
    exit 1
fi

# install.sh frågar annars interaktivt om driftläge/WAN-kort (läser /dev/tty),
# vilket inte finns i en systemd-tjänst. Detektera nuvarande läge och WAN-kort
# och skicka dem som flaggor så att inget prompt triggas. Läget avgörs av om
# agent-tjänsten redan startas med --mode=host; WAN-kortet tas från den enda
# default-rutten (WAN), med failsafe-regelsetet som reserv.
MODE="gateway"
if grep -q -- '--mode=host' /etc/systemd/system/security-harbor-agent.service 2>/dev/null; then
    MODE="host"
fi
INSTALL_ARGS=("--mode=$MODE")
if [ "$MODE" = "gateway" ]; then
    WAN_DEV="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
    if [ -z "$WAN_DEV" ] && [ -f /etc/security-harbor/security-harbor-failsafe.nft ]; then
        WAN_DEV="$(grep -oE 'iifname "[^"]+"' /etc/security-harbor/security-harbor-failsafe.nft 2>/dev/null | head -1 | sed -E 's/iifname "([^"]+)"/\1/')"
    fi
    [ -n "$WAN_DEV" ] && INSTALL_ARGS+=("--wan-device=$WAN_DEV")
fi

log "kör install.sh --mode=$MODE (idempotent uppdatering av binärer, webb-GUI, systemd)..."
# install.sh känner av en redan installerad maskin och rör inte
# /var/lib/security-harbor (config/db/nycklar).
( cd "$WORK" && ./install.sh "${INSTALL_ARGS[@]}" )

# install.sh startar SJÄLV om agenten (steg 7) — den nya binären är redan på
# plats när det sker. En omstart här ovanpå gjorde att hela boot-appliceringen
# kördes TVÅ gånger: unbound, kea, haproxy och suricata startades om två gånger
# i rad, vilket dubblade avbrottet för klienterna vid varje uppdatering
# (uppmätt 2026-08-26). Starta därför bara om något gick fel och tjänsten inte
# kör.
if systemctl is-active --quiet security-harbor-agent.service; then
    log "agenten kör redan på den nya versionen (omstartad av install.sh)."
else
    log "agenten kör inte efter install.sh - startar den..."
    systemctl restart security-harbor-agent.service
fi

log "klart. Städar staging."
rm -f "$TARBALL" "$SIG" "$STAGING_DIR/staged-version.txt"
