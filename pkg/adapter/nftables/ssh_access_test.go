package nftables

import (
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// SSH-åtkomsten till brandväggen styrs ENBART av policylistan.
//
// Fram till 2026-08-31 fanns en implicit "Garanterad SSH-åtkomst" som
// byggdes oberoende av policyerna och släppte in tcp/22 från ALLA interna
// kort — gäst-nät, IoT-VLAN och DMZ inräknade — utan att gå att redigera
// eller stänga av. Standard är fortfarande att LAN når SSH, men numera via
// den vanliga policyn sys-ssh-lan, som ägaren av brandväggen får ändra.
//
// De här testerna vaktar att den implicita öppningen inte smyger tillbaka.

// sshAcceptRules returnerar de INPUT-regler som accepterar tcp/22.
func sshAcceptRules(t *testing.T, cfg *config.Config) []Rule {
	t.Helper()
	var out []Rule
	for _, r := range renderRules(t, cfg) {
		if r.Chain != "input" {
			continue
		}
		expr := exprJSON(t, r)
		if strings.Contains(expr, `"dport"`) && strings.Contains(expr, "22") &&
			strings.Contains(expr, "accept") {
			out = append(out, r)
		}
	}
	return out
}

func TestNoSSHOpeningWithoutPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{"gateway utan policyer", &config.Config{
			Interfaces: []config.Interface{
				{Device: "ens18", Zone: "WAN", Enabled: true},
				{Device: "ens19", Zone: "LAN", Enabled: true},
			},
		}},
		{"host-läge utan policyer", &config.Config{
			Settings:   config.Settings{Mode: config.ModeHost},
			Interfaces: []config.Interface{{Device: "ens18", Zone: "HOST", Enabled: true}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rules := sshAcceptRules(t, tc.cfg); len(rules) != 0 {
				t.Fatalf("tcp/22 öppnas utan att någon policy säger det: %+v", rules)
			}
		})
	}
}

// Med den seedade standardpolicyn (LAN → SELF, 22) ska SSH släppas in på
// LAN-kortet och INGET annat internt kort. Det var precis det den implicita
// regeln bröt mot.
func TestSSHPolicyAppliesToItsZoneOnly(t *testing.T) {
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{Device: "ens18", Zone: "WAN", Enabled: true},
			{Device: "ens19", Zone: "LAN", Enabled: true},
			{Device: "ens20", Zone: "IOT", Enabled: true},
			{Device: "ens21", Zone: "DMZ", Enabled: true},
		},
		Zones: []config.Zone{{Name: "LAN"}, {Name: "IOT"}, {Name: "DMZ"}, {Name: "WAN"}},
		Policies: []config.Policy{{
			ID: "sys-ssh-lan", Name: "Tillåt SSH till brandväggen", Enabled: true,
			Local: true, Action: config.ActionAccept, Service: "22",
			SourceZone: "LAN", DestZone: "SELF",
		}},
	}

	rules := sshAcceptRules(t, cfg)
	if len(rules) == 0 {
		t.Fatal("standardpolicyn öppnar inte SSH på LAN")
	}
	for _, r := range rules {
		expr := exprJSON(t, r)
		if !strings.Contains(expr, "ens19") {
			t.Errorf("SSH-regeln är inte bunden till LAN-kortet: %s", expr)
		}
		for _, dev := range []string{"ens18", "ens20", "ens21"} {
			if strings.Contains(expr, dev) {
				t.Errorf("SSH öppnas mot kortet %s som inte ligger i LAN: %s", dev, expr)
			}
		}
	}
}

// Stänger man av SSH-policyn ska porten faktiskt stängas. Med livlinan kvar
// gick det inte: regeln byggdes ändå, och GUI:t visade en avstängd policy
// samtidigt som porten stod öppen.
func TestDisablingSSHPolicyClosesPort(t *testing.T) {
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{Device: "ens18", Zone: "WAN", Enabled: true},
			{Device: "ens19", Zone: "LAN", Enabled: true},
		},
		Zones: []config.Zone{{Name: "LAN"}, {Name: "WAN"}},
		Policies: []config.Policy{{
			ID: "sys-ssh-lan", Name: "Tillåt SSH till brandväggen", Enabled: false,
			Local: true, Action: config.ActionAccept, Service: "22",
			SourceZone: "LAN", DestZone: "SELF",
		}},
	}
	if rules := sshAcceptRules(t, cfg); len(rules) != 0 {
		t.Fatalf("SSH-porten är öppen trots att policyn är avstängd: %+v", rules)
	}
}
