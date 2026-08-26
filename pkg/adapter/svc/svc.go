// Package svc innehåller det som är gemensamt för adaptrarnas hantering av
// systemd-tjänster: skriv konfigurationen, och starta BARA om tjänsten om den
// faktiskt behöver det.
//
// Bakgrunden (rapporterat 2026-08-26): varje adapter körde `systemctl restart`
// ovillkorligt vid varje applicering. En agentuppdatering — som gör en full
// boot-applicering — slog därför ner unbound, kea, haproxy och suricata även
// när deras konfiguration var identisk med den som redan låg på disk. För
// klienterna på LAN:et syns det som att internet försvinner: DNS är nere i
// flera sekunder, och Suricatas omstart (~68 500 ET Open-regler) tog ensam
// 36 av appliceringens 41 sekunder.
//
// En omstart behövs bara när konfigurationen ÄNDRATS, eller när tjänsten inte
// redan kör. Är båda uppfyllda är omstarten ren nedtid utan nytta.
package svc

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// WriteIfChanged skriver data till path och returnerar true om innehållet
// faktiskt skiljde sig från det som redan låg där.
//
// Skrivningen är atomär (temp-fil i samma katalog + rename), så en tjänst
// aldrig läser en halvskriven konfiguration. Att temp-filen skapas i MÅL-
// katalogen är medvetet: skrivbarheten hänger på att katalogen är
// grupp-skrivbar för tjänstekontot, inte på målfilens ägare — paketen
// installerar sina conf-filer som root:root, och en direkt skrivning (O_TRUNC)
// på en sådan fil failar med "permission denied" även när katalogen är
// skrivbar.
func WriteIfChanged(path string, data []byte) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return false, nil
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op efter en lyckad rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	// CreateTemp ger 0600; conf-filerna måste vara läsbara för tjänsternas
	// egna konton.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return false, err
	}
	return true, nil
}

// IsActive svarar på om en systemd-enhet kör. `systemctl is-active` returnerar
// exit != 0 för allt utom "active", så utskriften — inte felkoden — avgör.
func IsActive(unit string) bool {
	out, _ := exec.Command("systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out)) == "active"
}

// RestartIfNeeded startar om enheten bara när det behövs: konfigurationen har
// ändrats, eller tjänsten kör inte redan.
//
// Returnerar även om en omstart faktiskt gjordes, så anroparen kan logga det.
func RestartIfNeeded(ctx context.Context, unit string, configChanged bool) (bool, error) {
	if !configChanged && IsActive(unit) {
		return false, nil
	}
	if out, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput(); err != nil {
		return true, fmt.Errorf("systemctl restart %s misslyckades: %w - output: %s", unit, err, string(out))
	}
	return true, nil
}
