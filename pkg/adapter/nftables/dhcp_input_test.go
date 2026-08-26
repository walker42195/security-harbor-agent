package nftables

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// Regression (rapporterat skarpt 2026-08-26): en Pixel 8 Pro på VLAN 9
// förnyade sin lease med unicast till 10.9.9.1:67 och nekades av DefaultDeny.
// Nätet fungerade ändå — Kea tar emot den FÖRSTA förfrågan via raw-socket,
// utanför INPUT-kedjan — men varje förnyelse föll tillbaka på broadcast och
// loggades som DENY. Regeln måste finnas.
func TestDHCPInputRuleOnServingInterfaces(t *testing.T) {
	cfg := multiVlanCfg()
	for i := range cfg.Interfaces {
		if cfg.Interfaces[i].Device == "ens19.9" {
			cfg.Interfaces[i].DHCP = &config.DHCPConfig{Enabled: true}
		}
	}

	rules := inputRulesFor(t, cfg, "Allow DHCP")
	if len(rules) != 1 {
		t.Fatalf("förväntade 1 DHCP-regel, fick %d", len(rules))
	}
	if !strings.Contains(rules[0].Comment, "ens19.9") {
		t.Errorf("DHCP-regeln gäller fel kort: %q", rules[0].Comment)
	}
	raw, err := json.Marshal(rules[0].Expr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"dport"`) || !strings.Contains(string(raw), "67") {
		t.Errorf("DHCP-regeln matchar inte UDP dport 67: %s", raw)
	}
}

// Ett kort UTAN DHCP-server ska inte ha porten öppen. En klient på ett nät
// där brandväggen inte delar ut adresser har ingen anledning att nå port 67
// på den, och en onödigt öppen port är en onödigt öppen port.
func TestDHCPInputRuleAbsentWithoutServer(t *testing.T) {
	if rules := inputRulesFor(t, multiVlanCfg(), "Allow DHCP"); len(rules) != 0 {
		t.Errorf("DHCP-regel renderad trots att ingen DHCP-server är på: %d st", len(rules))
	}
}

// WAN får ALDRIG öppnas för DHCP-server. Skulle någon sätta DHCP.Enabled på
// ett WAN-kort vore en DHCP-server mot internet både meningslös och skadlig.
func TestDHCPInputRuleNeverOnWAN(t *testing.T) {
	cfg := multiVlanCfg()
	for i := range cfg.Interfaces {
		if cfg.Interfaces[i].Zone == "WAN" {
			cfg.Interfaces[i].DHCP = &config.DHCPConfig{Enabled: true}
		}
	}
	for _, r := range inputRulesFor(t, cfg, "Allow DHCP") {
		for _, wan := range []string{"ens18", "eth0"} {
			if strings.Contains(r.Comment, wan) {
				t.Errorf("DHCP öppnad på WAN-kort: %q", r.Comment)
			}
		}
	}
}
