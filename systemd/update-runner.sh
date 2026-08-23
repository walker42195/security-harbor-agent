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

log "kör install.sh (idempotent uppdatering av binärer, webb-GUI, systemd)..."
# Bevara nuvarande driftläge (gateway/host) - install.sh känner av redan
# installerad maskin och rör inte /var/lib/security-harbor (config/db/nycklar).
( cd "$WORK" && ./install.sh )

log "startar om agenten på den nya versionen..."
systemctl restart security-harbor-agent.service

log "klart. Städar staging."
rm -f "$TARBALL" "$SIG" "$STAGING_DIR/staged-version.txt"
