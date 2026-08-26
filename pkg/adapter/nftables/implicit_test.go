package nftables

import (
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func fullCfg() *config.Config {
	cfg := multiVlanCfg()
	cfg.DNS = &config.DNSConfig{Enabled: true}
	cfg.NTP = &config.NTPConfig{Enabled: true}
	cfg.WireGuard = &config.WireGuardConfig{Enabled: true, ListenPort: 51820}
	cfg.OpenVPN = &config.OpenVPNConfig{Enabled: true, ListenPort: 443, Protocol: "udp"}
	return cfg
}

// Beskrivningarna MÅSTE spegla de regler som faktiskt renderas. Utan det här
// testet glider de isär tyst, och GUI:t visar en lista som inte stämmer med
// vad kärnan gör — vilket är värre än att inte visa något alls.
func TestImplicitRulesMatchRendered(t *testing.T) {
	cfg := fullCfg()

	// Kommentarsprefix i den renderade regeln för varje beskriven regel.
	commentFor := map[string]string{
		"Loopback":                "Allow loopback",
		"Etablerade anslutningar": "Allow established/related connections",
		"WireGuard VPN":           "Allow WireGuard",
		"OpenVPN":                 "Allow OpenVPN",
		"WAN Drop":                "HARD WAN DROP",
		"NTP till brandväggen":    "Allow NTP",
		"DNS till brandväggen":    "Allow DNS",
	}

	var inputComments []string
	for _, r := range renderRules(t, cfg) {
		if r.Chain == "input" {
			inputComments = append(inputComments, r.Comment)
		}
	}

	described := DescribeImplicitRules(cfg)
	if len(described) != len(commentFor) {
		t.Fatalf("beskrivna regler: %d, förväntade %d", len(described), len(commentFor))
	}

	// 1. Varje beskriven regel finns renderad.
	for _, d := range described {
		prefix, ok := commentFor[d.Name]
		if !ok {
			t.Errorf("okänd beskriven regel %q — lägg till den i testets karta", d.Name)
			continue
		}
		found := false
		for _, c := range inputComments {
			if strings.HasPrefix(c, prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("beskriven regel %q renderas inte (sökte %q)", d.Name, prefix)
		}
	}

	// 2. Ingen implicit regel saknar beskrivning. Policyregler har sina egna
	// namn som kommentar och räknas inte hit.
	for _, c := range inputComments {
		if !strings.HasPrefix(c, "Allow ") && !strings.HasPrefix(c, "HARD ") {
			continue
		}
		matched := false
		for _, prefix := range commentFor {
			if strings.HasPrefix(c, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("renderad implicit regel %q saknar beskrivning i DescribeImplicitRules", c)
		}
	}
}

// Avstängda funktioner ska inte beskrivas — annars listar GUI:t regler som
// inte finns i kärnan.
func TestDisabledFeaturesAreNotDescribed(t *testing.T) {
	cfg := multiVlanCfg() // ingen DNS, NTP, VPN
	names := map[string]bool{}
	for _, d := range DescribeImplicitRules(cfg) {
		names[d.Name] = true
	}
	for _, gone := range []string{"NTP till brandväggen", "DNS till brandväggen", "WireGuard VPN", "OpenVPN"} {
		if names[gone] {
			t.Errorf("%q beskrevs trots att funktionen är avstängd", gone)
		}
	}
	// Grundreglerna finns alltid.
	for _, always := range []string{"Loopback", "Etablerade anslutningar", "WAN Drop"} {
		if !names[always] {
			t.Errorf("%q saknas — den finns alltid", always)
		}
	}
}

// Loopback och established får ALDRIG loggas: de matchar varje paket i varje
// anslutning, och en loggrad per paket vore gigabyte per timme.
func TestHighVolumeRulesAreNotLogged(t *testing.T) {
	for _, d := range DescribeImplicitRules(fullCfg()) {
		if d.Name == "Loopback" || d.Name == "Etablerade anslutningar" {
			if d.Logged {
				t.Errorf("%q är markerad som loggad", d.Name)
			}
		}
	}
	// ...och det ska stämma med den faktiska regeln.
	for _, r := range renderRules(t, fullCfg()) {
		if r.Chain != "input" {
			continue
		}
		if strings.HasPrefix(r.Comment, "Allow loopback") ||
			strings.HasPrefix(r.Comment, "Allow established") {
			if strings.Contains(exprJSON(t, r), "SH-") {
				t.Errorf("%q loggar trots att den inte får: %s", r.Comment, exprJSON(t, r))
			}
		}
	}
}

func TestNilConfigIsSafe(t *testing.T) {
	if DescribeImplicitRules(nil) != nil {
		t.Error("nil-config ska ge nil")
	}
}
