package ntp

import (
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func cfg(enabled bool) *config.Config {
	return &config.Config{
		NTP: &config.NTPConfig{Enabled: enabled, ServeWhenUnsynced: true},
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, IPv4: "100.73.240.173/19"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, IPv4: "10.0.0.1/24"},
			{ID: "vlan9", Device: "ens19.9", Zone: "VLAN 9", Enabled: true, IPv4: "10.9.9.1/24"},
			{ID: "vlan8", Device: "ens19.8", Zone: "VLAN 8", Enabled: false, IPv4: "10.8.8.1/24"},
		},
	}
}

// Det viktigaste testet: en NTP-server nåbar från internet är ett klassiskt
// förstärkningsverktyg för DDoS. WAN-nätet får ALDRIG hamna i en allow-rad.
func TestWANIsNeverAllowed(t *testing.T) {
	out := GenerateConfig(cfg(true))
	if strings.Contains(out, "100.73") {
		t.Fatalf("WAN-nätet hamnade i konfigurationen:\n%s", out)
	}
}

func TestAllowsEnabledInternalNetworks(t *testing.T) {
	out := GenerateConfig(cfg(true))
	if !strings.Contains(out, "allow 10.0.0.0/24") {
		t.Errorf("LAN saknas:\n%s", out)
	}
	if !strings.Contains(out, "allow 10.9.9.0/24") {
		t.Errorf("VLAN 9 saknas:\n%s", out)
	}
	// Avstängt gränssnitt ska inte ge behörighet.
	if strings.Contains(out, "10.8.8") {
		t.Errorf("avstängt VLAN fick behörighet:\n%s", out)
	}
}

func TestNetworkIsSubnetNotHostAddress(t *testing.T) {
	// "allow 10.0.0.1/24" hade varit fel — chrony vill ha nätet.
	out := GenerateConfig(cfg(true))
	if strings.Contains(out, "allow 10.0.0.1/24") {
		t.Errorf("värdadressen användes i stället för nätet:\n%s", out)
	}
}

func TestDisabledGivesEmptyConfig(t *testing.T) {
	if out := GenerateConfig(cfg(false)); out != "" {
		t.Errorf("avstängd NTP gav ändå konfiguration:\n%s", out)
	}
	if out := GenerateConfig(&config.Config{}); out != "" {
		t.Errorf("saknad NTP-sektion gav konfiguration:\n%s", out)
	}
}

func TestServeWhenUnsyncedIsOptional(t *testing.T) {
	c := cfg(true)
	if !strings.Contains(GenerateConfig(c), "local stratum 10") {
		t.Error("local stratum saknas när ServeWhenUnsynced är på")
	}
	c.NTP.ServeWhenUnsynced = false
	if strings.Contains(GenerateConfig(c), "local stratum") {
		t.Error("local stratum skrevs trots att flaggan är av")
	}
}

// Stabil utskrift, annars ser varje applicering ut som en ändring och startar
// om chrony i onödan — vilket kan ge ett hopp i klockan.
func TestOutputIsDeterministic(t *testing.T) {
	c := cfg(true)
	first := GenerateConfig(c)
	c.Interfaces[1], c.Interfaces[2] = c.Interfaces[2], c.Interfaces[1]
	if GenerateConfig(c) != first {
		t.Error("gränssnittens ordning ändrade utskriften")
	}
}

func TestNoInternalNetworksStillWritesFile(t *testing.T) {
	c := cfg(true)
	c.Interfaces = c.Interfaces[:1] // bara WAN
	out := GenerateConfig(c)
	if out == "" {
		t.Fatal("tom utskrift lämnar en gammal fil kvar med behörigheter som inte gäller")
	}
	if strings.Contains(out, "allow ") {
		t.Errorf("allow utan interna nät:\n%s", out)
	}
}
