package engine

import (
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// Host-läge har inga klienter som får brandväggen som gateway och DNS, så
// varningen om DHCP på ett internt kort är meningslös där — den går inte ens
// att åtgärda. Rapporterat 2026-08-30: en host-installation visade
// "Gränssnittet ens18 (zon LAN) hämtar sin adress via DHCP" för ett kort som
// lagts till i efterhand och därmed hamnat i zon LAN, en zon som inte ens
// finns i host-lägets zonlista.
func TestNoLANDHCPWarningInHostMode(t *testing.T) {
	cfg := &config.Config{
		Settings: config.Settings{Mode: config.ModeHost},
		Zones:    []config.Zone{{Name: "HOST"}},
		Interfaces: []config.Interface{
			{ID: "host0", Device: "ens19", Zone: "HOST", Enabled: true, AddressType: "dhcp"},
			// Kort tillagt i efterhand — GUI:t ger det zon LAN.
			{ID: "if_1", Device: "ens18", Zone: "LAN", Enabled: true, AddressType: "dhcp"},
		},
	}
	if w := lanDHCPWarnings(cfg); len(w) != 0 {
		var msgs []string
		for _, x := range w {
			msgs = append(msgs, x.Message)
		}
		t.Errorf("host-läge gav %d varning(ar):\n  %s", len(w), strings.Join(msgs, "\n  "))
	}
}

// Gateway-läge måste fortfarande varna: där ÄR det ett riktigt problem att
// brandväggens interna kort byter adress, eftersom klienterna har den som
// gateway och DNS.
func TestLANDHCPWarningStillFiresInGatewayMode(t *testing.T) {
	cfg := &config.Config{
		Zones: []config.Zone{{Name: "WAN"}, {Name: "LAN"}},
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "dhcp"},
		},
	}
	w := lanDHCPWarnings(cfg)
	if len(w) != 1 {
		t.Fatalf("gateway-läge: förväntade 1 varning, fick %d", len(w))
	}
	if !strings.Contains(w[0].Message, "ens19") {
		t.Errorf("varningen pekar inte ut LAN-kortet: %s", w[0].Message)
	}
	// WAN-kortet ska aldrig varnas för — DHCP där är det normala.
	if strings.Contains(w[0].Message, "ens18") {
		t.Errorf("varnade för WAN-kortet: %s", w[0].Message)
	}
}
