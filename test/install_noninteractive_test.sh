#!/bin/bash
# Regressionstest för självuppdateringen (trasig i 0.45.0/0.45.1).
#
# install.sh körs av update-runner.sh från en systemd-oneshot UTAN
# kontrollerande terminal. Steg 5 (kortvalet) frågade då interaktivt och
# `read </dev/tty` dog med "No such device or address", vilket fällde hela
# uppdateringen mitt i.
#
# Felet doldes av att guarden testade `[ -r /dev/tty ]`. Enhetsnoden FINNS och
# är läsbar för root i en systemd-tjänst — det som saknas är en kontrollerande
# terminal, och det märks först vid open(). Testet kontrollerar båda delarna:
# att rätt test används överallt, och att det faktiskt svarar nej utan
# terminal.
set -u
cd "$(dirname "$0")/.."
FAILED=0

fail() { echo "FAIL: $*"; FAILED=1; }
ok()   { echo "ok:   $*"; }

# 1. have_tty måste svara NEJ när den kontrollerande terminalen är borta.
#    setsid kopplar bort den och återskapar systemd-oneshotens villkor exakt.
probe=$(mktemp)
sed -n '/^have_tty() {/,/^}/p' install.sh > "$probe"
if ! grep -q "have_tty" "$probe"; then
    fail "hittade ingen have_tty-funktion i install.sh"
else
    echo 'if have_tty; then echo JA; else echo NEJ; fi' >> "$probe"
    res="$(setsid bash "$probe" </dev/null 2>&1)"
    if [ "$res" = "NEJ" ]; then
        ok "have_tty svarar nej utan kontrollerande terminal"
    else
        fail "have_tty svarade '$res' utan kontrollerande terminal"
    fi
    # ... och ja när det FINNS en terminal, annars vore den värdelös.
    if command -v script >/dev/null 2>&1; then
        res="$(script -qec "bash $probe" /dev/null 2>&1 | tr -d '\r\n')"
        if [ "$res" = "JA" ]; then
            ok "have_tty svarar ja med terminal"
        else
            fail "have_tty svarade '$res' MED terminal - guarden är för sträng"
        fi
    fi
fi
rm -f "$probe"

# 2. Ingen får ha kvar det gamla, felaktiga testet.
for f in install.sh systemd/update-runner.sh systemd/rollback-runner.sh; do
    [ -f "$f" ] || continue
    # grep -v '^\s*#': bara KOD, inte kommentarer som beskriver det gamla felet.
    if grep -nE '\[[[:space:]]*-r[[:space:]]+/dev/tty[[:space:]]*\]' "$f" | grep -vE '^[0-9]+:[[:space:]]*#'; then
        fail "$f använder '[ -r /dev/tty ]' - det är sant i en systemd-tjänst"
    else
        ok "$f saknar det felaktiga -r /dev/tty-testet"
    fi
done

# 3. Varje läsning från /dev/tty måste ligga bakom have_tty.
while IFS= read -r line; do
    n="${line%%:*}"
    start=$(( n > 12 ? n - 12 : 1 ))
    if ! sed -n "${start},${n}p" install.sh | grep -q "have_tty"; then
        fail "install.sh rad $n läser från /dev/tty utan have_tty-guard inom 12 rader"
    else
        ok "install.sh rad $n är guardad av have_tty"
    fi
done < <(grep -n 'read .*</dev/tty' install.sh | grep -vE '^[0-9]+:[[:space:]]*#')

# 4. Uppgraderingsvägen: install.sh måste återanvända tidigare kortval ur den
#    installerade enhetens ExecStart, annars frågar den vid varje uppdatering.
#    Kör den FAKTISKA funktionen mot en riktig ExecStart-rad — en `grep -q
#    prev_flag` hade passerat även när funktionen var trasig, vilket den var:
#    "--" skickades som $1 och mönstret matchade aldrig något.
prev=$(mktemp)
sed -n '/^  prev_flag() {/,/^  }/p' install.sh | sed 's/^  //' > "$prev"
if ! grep -q 'prev_flag' "$prev"; then
    fail "hittade ingen prev_flag-funktion i install.sh"
else
    cat >> "$prev" <<'INNER'
PREV_EXEC='ExecStart=/usr/local/bin/security-harbor-agent --data-dir /var/lib/security-harbor --mode=host --host-device=ens19 --wan-device=ens18 --lan-device=ens20'
echo "host=$(prev_flag --host-device) wan=$(prev_flag --wan-device) lan=$(prev_flag --lan-device)"
INNER
    got="$(bash "$prev" 2>&1)"
    want="host=ens19 wan=ens18 lan=ens20"
    if [ "$got" = "$want" ]; then
        ok "prev_flag läser tidigare kortval ur ExecStart"
    else
        fail "prev_flag gav '$got', förväntade '$want'"
    fi
fi
rm -f "$prev"

# 5. update-runner.sh kör med `set -euo pipefail`. En grep som inte matchar
#    returnerar 1 och dödar då hela uppdateringen tyst. Det hände skarpt:
#    host-läge har ingen --wan-device i ExecStart, grep sa 1, och
#    självuppdateringen dog direkt efter "packar upp bunten" utan felmeddelande.
#    Kör den faktiska loopen mot en host-ExecStart (som saknar två av tre
#    flaggor) under samma flaggor som skriptet självt använder.
runner=$(mktemp)
{
    echo 'set -euo pipefail'
    echo "PREV_EXEC='ExecStart=/usr/local/bin/security-harbor-agent --data-dir /var/lib/security-harbor --mode=host --host-device=ens19'"
    echo 'INSTALL_ARGS=("--mode=host")'
    sed -n '/^for _flag in --host-device/,/^done$/p' systemd/update-runner.sh
    echo 'echo "ARGS=${INSTALL_ARGS[*]}"'
} > "$runner"
got="$(bash "$runner" 2>&1)"; rc=$?
rm -f "$runner"
if [ $rc -ne 0 ]; then
    fail "update-runner-loopen avslutar med $rc när en flagga saknas (set -e + pipefail): $got"
elif [ "$got" != "ARGS=--mode=host --host-device=ens19" ]; then
    fail "update-runner-loopen gav '$got'"
else
    ok "update-runner-loopen överlever flaggor som saknas"
fi

exit $FAILED
