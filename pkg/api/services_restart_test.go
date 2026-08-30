package api

import (
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// Omstartsknappen får inte kunna starta en tjänst vars funktion är avstängd.
// Agenten äger start/stopp: stoppar den suricata när IDS slås av, och någon
// sedan trycker "starta om", säger konfigurationen en sak och maskinen en
// annan. Rapporterat 2026-08-30 på en skarp gateway — IDS var avstängt men
// suricata.service kördes, och panelen såg ut som att IDS var på.
func TestServiceConfiguredGatesRestart(t *testing.T) {
	off := &config.Config{IDS: &config.IDSConfig{Enabled: false}}
	on := &config.Config{IDS: &config.IDSConfig{Enabled: true}}

	if serviceConfigured("ids", off) {
		t.Error("IDS avstängt i configen ska inte räknas som konfigurerat")
	}
	if !serviceConfigured("ids", on) {
		t.Error("IDS påslaget i configen ska räknas som konfigurerat")
	}

	// Agenten själv måste ALLTID gå att starta om — den har ingen på/av-flagga,
	// och en spärr där hade tagit bort den enda vägen att starta om
	// administrationsgränssnittet från GUI:t.
	if !serviceConfigured("agent", off) {
		t.Error("agenten ska alltid vara startbar")
	}
	if !serviceConfigured("agent", nil) {
		t.Error("agenten ska vara startbar även utan config")
	}

	// Utan config vet vi ingenting — då ska inget annat än agenten startas.
	for _, id := range []string{"ids", "dns", "dhcp", "openvpn", "syslog"} {
		if serviceConfigured(id, nil) {
			t.Errorf("%q räknades som konfigurerat utan config", id)
		}
	}
}
