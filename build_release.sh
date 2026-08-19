#!/bin/bash
# Security Harbor Agent - paketera en fristående installationsbunt.
# Cross-kompilerar alla binärer för linux/amd64 och samlar dem + samtliga
# systemd-enheter/polkit-regler + install.sh i ./dist, redo att kopieras
# till en ny maskin (scp/tar) och installeras med `sudo ./install.sh`.
set -e

cd "$(dirname "$0")"

DIST_DIR="dist"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo "=== 1. Cross-kompilerar binärer (linux/amd64) ==="
GOOS=linux GOARCH=amd64 go build -o "$DIST_DIR/security-harbor-agent" ./cmd/security-harbor-agent
GOOS=linux GOARCH=amd64 go build -o "$DIST_DIR/security-harbor-nmap-runner" ./cmd/security-harbor-nmap-runner
GOOS=linux GOARCH=amd64 go build -o "$DIST_DIR/security-harbor-tcpdump-runner" ./cmd/security-harbor-tcpdump-runner
echo "-> $DIST_DIR/security-harbor-agent, security-harbor-nmap-runner, security-harbor-tcpdump-runner"

echo "=== 2. Kopierar systemd-enheter, polkit-regler och failsafe-mallar ==="
mkdir -p "$DIST_DIR/systemd"
cp systemd/*.service systemd/*.timer systemd/*.rules systemd/*.nft.tmpl "$DIST_DIR/systemd/"

echo "=== 3. Kopierar install.sh och uninstall.sh ==="
cp install.sh "$DIST_DIR/install.sh"
cp uninstall.sh "$DIST_DIR/uninstall.sh"
chmod +x "$DIST_DIR/install.sh" "$DIST_DIR/uninstall.sh"

echo "=== 4. Paketerar som tarboll (för GitHub Release) ==="
tar -czf "security-harbor-dist.tar.gz" -C "$DIST_DIR" .
echo "-> security-harbor-dist.tar.gz"

echo "=== Klart: $DIST_DIR/ är en fristående installationsbunt ==="
echo "Antingen: kopiera katalogen till målmaskinen (scp -r dist/ user@host:/tmp/security-harbor-install)"
echo "och kör: sudo ./install.sh"
echo "Eller: bifoga security-harbor-dist.tar.gz på en GitHub Release (se README) för"
echo "att aktivera en-rads-installation via curl."
