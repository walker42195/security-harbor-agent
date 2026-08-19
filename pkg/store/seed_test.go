package store

import (
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func TestDefaultSeedConfigHostModeIsTopologyNeutral(t *testing.T) {
	cfg := defaultSeedConfig(config.ModeHost)

	if cfg.Settings.Mode != config.ModeHost {
		t.Fatalf("förväntade Settings.Mode=%q, fick %q", config.ModeHost, cfg.Settings.Mode)
	}
	if len(cfg.Interfaces) != 1 {
		t.Fatalf("förväntade exakt ett interface i host-läge, fick %d", len(cfg.Interfaces))
	}
	if cfg.Interfaces[0].Zone == "WAN" || cfg.Interfaces[0].Zone == "LAN" {
		t.Fatalf("host-läges-seedet ska inte tvinga WAN/LAN-zon, fick %q", cfg.Interfaces[0].Zone)
	}
	if cfg.Policies[0].SourceZone != cfg.Zones[0].Name {
		t.Fatalf("SSH-policyns SourceZone (%q) matchar inte den enda seedade zonen (%q)",
			cfg.Policies[0].SourceZone, cfg.Zones[0].Name)
	}
}

func TestDefaultSeedConfigGatewayModeUnchanged(t *testing.T) {
	for _, mode := range []string{"", config.ModeGateway} {
		cfg := defaultSeedConfig(mode)
		var hasWAN, hasLAN bool
		for _, iface := range cfg.Interfaces {
			if iface.Zone == "WAN" {
				hasWAN = true
			}
			if iface.Zone == "LAN" {
				hasLAN = true
			}
		}
		if !hasWAN || !hasLAN {
			t.Fatalf("mode=%q: förväntade både WAN- och LAN-interface (bakåtkompatibelt default), fick interfaces=%+v", mode, cfg.Interfaces)
		}
	}
}
