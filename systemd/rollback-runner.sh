#!/bin/bash
# Security Harbor - privilegierad rollback-installer.
#
# Körs som root av security-harbor-rollback@<version>.service (mall-enhet,
# oneshot), triggad av den oprivilegierade agenten via
# `systemctl start --no-block security-harbor-rollback@<version>.service`
# (se pkg/api/server.go:handleRollbackVersion).
#
# Till skillnad från update-runner.sh hämtas INGET nytt från nätet och
# INGEN signatur verifieras om - den arkiverade versionen har redan körts
# och verifierats på den här maskinen tidigare (samma tillitsnivå som
# vilken annan root-ägd fil på disk som helst). Detta skript gör bara ett
# rent filbyte + omstart: INGEN apt-paketinstallation, INGEN
# user/group-setup, INGEN permission-fixup, INGEN
# failsafe-regelsetsgenerering och ingen MODE/WAN-fråga - allt det hör
# hemma i install.sh och behöver inte köras om för en rollback inom samma
# installation.
set -euo pipefail

DATA_DIR="/var/lib/security-harbor"
BIN_DIR="/usr/local/bin"
VERSIONS_DIR="$DATA_DIR/versions"
LIB_DIR="/usr/local/lib/security-harbor"
AGENT_BIN="$BIN_DIR/security-harbor-agent"

log() { echo "[sh-rollback] $*"; }

# Ömsesidig uteslutning mot en samtidig security-harbor-update.service (eller
# en annan rollback-instans) - båda skulle annars kunna byta ut binärer/webui/
# enheter samtidigt. Icke-blockerande: vägrar starta hellre än att köa och
# riskera en halvfärdig filkopiering.
LOCK_FILE="/var/lib/security-harbor/updates/.install.lock"
mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log "en annan uppdatering/rollback pågår redan - avbryter."
    exit 1
fi

TARGET="${1:-}"
if ! [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log "ogiltig målversion '$TARGET' - avbryter."
    exit 1
fi

SRC="$VERSIONS_DIR/$TARGET"
if [ ! -d "$SRC" ]; then
    log "version $TARGET finns inte bland sparade versioner ($SRC) - avbryter."
    exit 1
fi
if [ -f "$VERSIONS_DIR/index.json" ] && command -v jq >/dev/null 2>&1; then
    if ! jq -e --arg v "$TARGET" '.versions[] | select(.version == $v)' \
        "$VERSIONS_DIR/index.json" >/dev/null 2>&1; then
        log "version $TARGET finns på disk men saknas i index.json - avbryter (försvar i djupet)."
        exit 1
    fi
fi

CURRENT_VERSION="$("$AGENT_BIN" --version 2>/dev/null || true)"
if [ "$CURRENT_VERSION" = "$TARGET" ]; then
    log "redan på version $TARGET - ingenting att göra."
    exit 0
fi

log "arkiverar körande version $CURRENT_VERSION innan byte till $TARGET..."
if [ -f "$LIB_DIR/lib-archive-version.sh" ]; then
    # shellcheck source=lib-archive-version.sh
    . "$LIB_DIR/lib-archive-version.sh"
    archive_current_version "$TARGET"
fi

log "installerar binärer/webui/systemd-enheter från sparad version $TARGET..."
for bin in security-harbor-agent security-harbor-nmap-runner security-harbor-tcpdump-runner; do
    if [ -f "$SRC/$bin" ]; then
        install -m 0755 -o root -g root "$SRC/$bin" "$BIN_DIR/$bin"
    fi
done
if [ -f "$SRC/update-runner.sh" ]; then
    install -m 0755 -o root -g root "$SRC/update-runner.sh" "$LIB_DIR/update-runner.sh"
fi
if [ -f "$SRC/rollback-runner.sh" ]; then
    install -m 0755 -o root -g root "$SRC/rollback-runner.sh" "$LIB_DIR/rollback-runner.sh"
fi

if [ -d "$SRC/webui" ]; then
    install -d -m 0755 "$DATA_DIR/webui"
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete "$SRC/webui/" "$DATA_DIR/webui/"
    else
        rm -rf "${DATA_DIR:?}/webui"/*
        cp -a "$SRC/webui/." "$DATA_DIR/webui/"
    fi
    chown -R security-harbor:security-harbor "$DATA_DIR/webui"
fi

if [ -d "$SRC/systemd" ]; then
    for f in "$SRC/systemd"/*.service "$SRC/systemd"/*.timer; do
        [ -f "$f" ] && cp "$f" /etc/systemd/system/
    done
    for f in "$SRC/systemd"/*.rules; do
        [ -f "$f" ] && cp "$f" /etc/polkit-1/rules.d/
    done
    systemctl daemon-reload
fi

# OBS: konfigurationsfilen (running.json) migreras INTE automatiskt vid en
# nedgradering - en äldre agentversion kan sakna stöd för fält som skrivits
# av en senare version. Verifiera funktionen efter återställning (samma
# varning visas i GUI:t innan en rollback bekräftas).

log "startar om agenten på version $TARGET..."
systemctl restart security-harbor-agent.service

log "klart."
