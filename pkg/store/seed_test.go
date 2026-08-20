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

// TestDefaultSeedIncludesIPSAutoBlockObject: ett tomt standardobjekt
// "IPS - Auto block" ska finnas från start i BÅDA lägena, så IDS-sidan i
// GUI:t kan förifylla det. Auto-block ska dock INTE vara aktiverat som
// standard (IDSConfig sätts inte alls i seedet).
func TestDefaultSeedIncludesIPSAutoBlockObject(t *testing.T) {
	for _, mode := range []string{"", config.ModeGateway, config.ModeHost} {
		cfg := defaultSeedConfig(mode)
		var found *config.Object
		for i := range cfg.Objects {
			if cfg.Objects[i].Name == "IPS - Auto block" {
				found = &cfg.Objects[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("mode=%q: seedet saknar standardobjektet \"IPS - Auto block\"", mode)
		}
		if len(found.Values) != 0 {
			t.Errorf("mode=%q: standardobjektet ska vara tomt, hade %d värden", mode, len(found.Values))
		}
		if cfg.IDS != nil && cfg.IDS.AutoBlock {
			t.Errorf("mode=%q: auto-block ska INTE vara aktiverat som standard", mode)
		}
	}
}
