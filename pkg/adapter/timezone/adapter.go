// Package timezone sätter serverns tidszon.
//
// Tidszonen styr allt servern själv tidsstämplar — journald skriver lokal tid
// med offset, och det är den stämpeln trafikloggen visar. En server som står
// kvar på UTC medan administratören sitter i CEST ger en logg som ser två
// timmar fel ut fast ingenting är trasigt.
package timezone

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// safeName begränsar vad som får skickas till timedatectl. Värdet kommer från
// GUI:t och hamnar i ett kommandoargument; IANA-namn består bara av dessa
// tecken ("Europe/Stockholm", "America/Argentina/Buenos_Aires").
var safeName = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+){0,2}$`)

// Current läser serverns nuvarande tidszon.
func Current() string {
	out, err := exec.Command("timedatectl", "show", "-p", "Timezone", "--value").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Available listar de tidszoner systemet känner till, för GUI:ts väljare.
func Available() []string {
	out, err := exec.Command("timedatectl", "list-timezones").Output()
	if err != nil {
		return nil
	}
	var zones []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if z := strings.TrimSpace(line); z != "" {
			zones = append(zones, z)
		}
	}
	return zones
}

// Apply sätter tidszonen om den skiljer sig från den nuvarande.
//
// Tomt värde betyder "rör inte" — en installation som aldrig satt tidszonen i
// GUI:t ska behålla det som konfigurerades vid OS-installationen.
//
// Anropet går via systemd-timedated (D-Bus), som kräver polkit-behörighet för
// det oprivilegierade tjänstekontot; se
// systemd/10-security-harbor-timezone.rules.
func Apply(ctx context.Context, want string) error {
	want = strings.TrimSpace(want)
	if want == "" {
		return nil
	}
	if !safeName.MatchString(want) {
		return fmt.Errorf("%q är inte ett giltigt tidszonsnamn", want)
	}
	if Current() == want {
		return nil
	}
	out, err := exec.CommandContext(ctx, "timedatectl", "set-timezone", want).CombinedOutput()
	if err != nil {
		return fmt.Errorf("kunde inte sätta tidszon %s: %w - %s", want, err, strings.TrimSpace(string(out)))
	}
	return nil
}
