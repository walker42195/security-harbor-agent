package store

import (
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func TestDefaultSeedConfigHostModeIsTopologyNeutral(t *testing.T) {
	cfg := defaultSeedConfig(SeedOptions{Mode: config.ModeHost, HostDevice: "eth-test0"})

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
		cfg := defaultSeedConfig(SeedOptions{Mode: mode, WANDevice: "wan-test0", LANDevice: "lan-test0", HostDevice: "eth-test0"})
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
		cfg := defaultSeedConfig(SeedOptions{Mode: mode, WANDevice: "wan-test0", LANDevice: "lan-test0", HostDevice: "eth-test0"})
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

// TestSeedUsesGivenDevices: seed-configen ska peka på DE KORT installationen
// angav, aldrig på ett hårdkodat namn. Regressionstest för utlåsningen
// 2026-08-30: host-seedet hade "eth0" fast inbakat, och på en maskin vars
// kort hette något annat (ens18) matchade SSH-/Management-policyerna inget
// alls — default drop tog all trafik och maskinen gick bara att rädda via
// konsolen.
func TestSeedUsesGivenDevices(t *testing.T) {
	host := defaultSeedConfig(SeedOptions{Mode: config.ModeHost, HostDevice: "enp3s0"})
	if got := host.Interfaces[0].Device; got != "enp3s0" {
		t.Errorf("host-läge: förväntade device %q, fick %q", "enp3s0", got)
	}

	gw := defaultSeedConfig(SeedOptions{WANDevice: "enp1s0", LANDevice: "enp2s0"})
	devByZone := map[string]string{}
	for _, iface := range gw.Interfaces {
		if iface.VLANID == 0 {
			devByZone[iface.Zone] = iface.Device
		}
	}
	if devByZone["WAN"] != "enp1s0" {
		t.Errorf("gateway-läge: WAN-device blev %q, förväntade %q", devByZone["WAN"], "enp1s0")
	}
	if devByZone["LAN"] != "enp2s0" {
		t.Errorf("gateway-läge: LAN-device blev %q, förväntade %q", devByZone["LAN"], "enp2s0")
	}
}

// TestSeedPoliciesMatchSeededZones: varje policy som ska släppa in
// administratören (SSH och Management-API) måste peka på en zon som
// FAKTISKT finns i seedet och har ett kort. En policy vars källzon inte
// mappar till något kort blir en regel som matchar noll paket — vilket är
// exakt hur utlåsningen såg ut i nftables.
func TestSeedPoliciesMatchSeededZones(t *testing.T) {
	for _, seed := range []SeedOptions{
		{Mode: config.ModeHost, HostDevice: "enp3s0"},
		{Mode: config.ModeGateway, WANDevice: "enp1s0", LANDevice: "enp2s0"},
	} {
		cfg := defaultSeedConfig(seed)
		zoneHasDevice := map[string]bool{}
		for _, iface := range cfg.Interfaces {
			if iface.Device != "" {
				zoneHasDevice[iface.Zone] = true
			}
		}
		for _, id := range []string{config.MgmtAPIPolicyID} {
			for _, p := range cfg.Policies {
				if p.ID != id || !p.Enabled {
					continue
				}
				if p.SourceZone != "" && p.SourceZone != "ANY" && !zoneHasDevice[p.SourceZone] {
					t.Errorf("mode=%q: policy %q har källzon %q som inget seedat kort tillhör",
						seed.Mode, p.ID, p.SourceZone)
				}
			}
		}
	}
}
