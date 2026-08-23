#!/bin/bash
# Security Harbor Agent - paketera en fristående, SIGNERAD installationsbunt.
# Cross-kompilerar alla binärer för linux/amd64 (med inbyggd version), bygger
# webb-GUI:t från sibling-repot, samlar allt + systemd-enheter/polkit-regler +
# install.sh i ./dist, signerar tarbollen (Ed25519) och skriver ett
# manifest.json. Redo att laddas upp som GitHub Release-assets (tarball,
# tarball.sig, manifest.json) för en-rads-installation OCH självuppdatering.
set -e

cd "$(dirname "$0")"

VERSION="$(tr -d ' \t\n\r' < VERSION)"
[ -n "$VERSION" ] || { echo "VERSION-filen är tom"; exit 1; }

# Webb-GUI:ts repo (sibling) och versionskälla (pubspec).
GUI_DIR="${GUI_DIR:-../security-harbor-gui}"
WEBUI_VERSION="$VERSION"
if [ -f "$GUI_DIR/pubspec.yaml" ]; then
  WEBUI_VERSION="$(grep -E '^version:' "$GUI_DIR/pubspec.yaml" | head -1 | sed -E 's/version:[[:space:]]*//; s/\+.*//' | tr -d ' \r')"
fi

# Privat signeringsnyckel (Ed25519, base64 av 64 bytes) - HÅLLS UTANFÖR REPOT.
SIGN_KEY="${SIGN_KEY:-$HOME/.config/security-harbor/release-signing.key}"

# Release-URL som stoppas in i manifestet (stabil "latest download"-URL).
RELEASE_BASE="${RELEASE_BASE:-https://github.com/walker42195/security-harbor-agent/releases/latest/download}"

DIST_DIR="dist"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo "=== 1. Cross-kompilerar binärer (linux/amd64), version $VERSION ==="
LDFLAGS="-X main.version=$VERSION"
GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$DIST_DIR/security-harbor-agent" ./cmd/security-harbor-agent
GOOS=linux GOARCH=amd64 go build -o "$DIST_DIR/security-harbor-nmap-runner" ./cmd/security-harbor-nmap-runner
GOOS=linux GOARCH=amd64 go build -o "$DIST_DIR/security-harbor-tcpdump-runner" ./cmd/security-harbor-tcpdump-runner
# Signeringsverktyget byggs för värdens plattform (används lokalt nedan).
go build -o "$DIST_DIR/security-harbor-sign" ./cmd/security-harbor-sign
echo "-> agent (v$VERSION), nmap-runner, tcpdump-runner, sign"

echo "=== 2. Bygger webb-GUI:t (flutter build web) från $GUI_DIR ==="
if [ -d "$GUI_DIR" ]; then
  ( cd "$GUI_DIR" && flutter build web --no-web-resources-cdn --pwa-strategy=none )
  mkdir -p "$DIST_DIR/webui"
  cp -a "$GUI_DIR/build/web/." "$DIST_DIR/webui/"
  # Versionsmarkör som agenten läser och rapporterar (se updater.ReadWebUIVersion).
  printf '{"version":"%s"}\n' "$WEBUI_VERSION" > "$DIST_DIR/webui/version.json"
  echo "-> webb-GUI v$WEBUI_VERSION i $DIST_DIR/webui"
else
  echo "VARNING: $GUI_DIR saknas - buntar UTAN webb-GUI (sätt GUI_DIR)." >&2
fi

echo "=== 3. Kopierar systemd-enheter, polkit-regler, failsafe-mallar och runner ==="
mkdir -p "$DIST_DIR/systemd"
cp systemd/*.service systemd/*.timer systemd/*.rules systemd/*.nft.tmpl "$DIST_DIR/systemd/"
cp systemd/update-runner.sh "$DIST_DIR/systemd/"
chmod +x "$DIST_DIR/systemd/update-runner.sh"

echo "=== 4. Kopierar install.sh och uninstall.sh ==="
cp install.sh "$DIST_DIR/install.sh"
cp uninstall.sh "$DIST_DIR/uninstall.sh"
chmod +x "$DIST_DIR/install.sh" "$DIST_DIR/uninstall.sh"

echo "=== 5. Paketerar som tarboll ==="
# security-harbor-sign ska INTE med i den installerade bunten - flytta ut den
# ur dist/ innan tarbollen skapas (den används bara lokalt för att signera).
mv "$DIST_DIR/security-harbor-sign" "./security-harbor-sign"
tar -czf "security-harbor-dist.tar.gz" -C "$DIST_DIR" .
echo "-> security-harbor-dist.tar.gz"

echo "=== 6. Signerar tarbollen (Ed25519) och skriver manifest.json ==="
if [ ! -f "$SIGN_KEY" ]; then
  echo "VARNING: signeringsnyckel saknas ($SIGN_KEY) - hoppar över signering/manifest." >&2
  echo "         Sätt SIGN_KEY eller lägg nyckeln på plats för att kunna publicera en release." >&2
  rm -f "./security-harbor-sign"
  exit 0
fi
SIG="$(./security-harbor-sign -key "$SIGN_KEY" -in security-harbor-dist.tar.gz)"
SHA="$(sha256sum security-harbor-dist.tar.gz | awk '{print $1}')"
cat > manifest.json <<EOF
{
  "firewall": {
    "version": "$VERSION",
    "webui_version": "$WEBUI_VERSION",
    "url": "$RELEASE_BASE/security-harbor-dist.tar.gz",
    "sha256": "$SHA",
    "sig": "$SIG"
  }
}
EOF
rm -f "./security-harbor-sign"
echo "-> security-harbor-dist.tar.gz.sig, manifest.json"

echo "=== Klart ==="
echo "Ladda upp som GitHub Release-assets: security-harbor-dist.tar.gz,"
echo "security-harbor-dist.tar.gz.sig och manifest.json."
echo "Lokal install/uppdatering: sudo ./dist/install.sh"
