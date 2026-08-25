package nftables

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func baseCfg() *config.Config {
	return &config.Config{
		Settings: config.Settings{APIPort: 8443},
		Zones:    []config.Zone{{Name: "WAN"}, {Name: "LAN"}},
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, IPv4: "203.0.113.10/24"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, IPv4: "10.0.0.1/24"},
		},
	}
}

func renderRules(t *testing.T, cfg *config.Config) []Rule {
	t.Helper()
	out, err := NewAdapter().RenderJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Nftables []struct {
			Rule *Rule `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &root); err != nil {
		t.Fatal(err)
	}
	var rules []Rule
	for _, e := range root.Nftables {
		if e.Rule != nil {
			rules = append(rules, *e.Rule)
		}
	}
	return rules
}

func exprJSON(t *testing.T, r Rule) string {
	t.Helper()
	b, err := json.Marshal(r.Expr)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Regression: prerouting-DNAT saknade iifname-villkor. Eftersom GUI:t aldrig
// sätter ExternalIP blev varje port forward "tcp dport X dnat to ..." utan
// gränssnittsvillkor — den matchade då ALL trafik mot porten, från alla
// gränssnitt, och kapade bl.a. LAN-klienters utgående trafik.
func TestDNATPreroutingIsBoundToInterface(t *testing.T) {
	cfg := baseCfg()
	cfg.Policies = []config.Policy{{
		ID: "p1", Name: "PF", Enabled: true, Action: config.ActionDNAT,
		NAT: &config.NATConfig{ExternalPort: 443, InternalIP: "10.0.0.5", InternalPort: 443, Protocol: "tcp"},
	}}

	found := 0
	for _, r := range renderRules(t, cfg) {
		if r.Chain != "prerouting" {
			continue
		}
		found++
		e := exprJSON(t, r)
		if !strings.Contains(e, "iifname") {
			t.Errorf("prerouting-regel %q saknar iifname-villkor: %s", r.Comment, e)
		}
		// Hairpin-regeln måste dessutom vara bunden till den externa adressen.
		if strings.Contains(r.Comment, "hairpin") && !strings.Contains(e, "203.0.113.10") {
			t.Errorf("hairpin-regeln saknar villkor på extern adress: %s", e)
		}
	}
	if found == 0 {
		t.Fatal("ingen prerouting-regel genererades alls")
	}
}

// Regression: FORWARD-följeregeln till en DNAT accepterade trafik mot
// InternalIP:port oavsett källa, så en isolerad zon nådde DNAT-målet förbi
// Default Deny. Den ska nu kräva att paketet FAKTISKT DNAT:ades.
func TestDNATForwardRequiresCtStatusDNAT(t *testing.T) {
	cfg := baseCfg()
	cfg.Policies = []config.Policy{{
		ID: "p1", Name: "PF", Enabled: true, Action: config.ActionDNAT,
		NAT: &config.NATConfig{ExternalPort: 443, InternalIP: "10.0.0.5", InternalPort: 443, Protocol: "tcp"},
	}}
	for _, r := range renderRules(t, cfg) {
		if r.Chain == "forward" && strings.Contains(r.Comment, "DNAT forwarding") {
			e := exprJSON(t, r)
			if !strings.Contains(e, `"ct"`) || !strings.Contains(e, "dnat") {
				t.Fatalf("DNAT-följeregeln saknar ct status dnat-villkor: %s", e)
			}
			return
		}
	}
	t.Fatal("hittade ingen DNAT-följeregel i forward-kedjan")
}

// Regression (fail-open): ett AKTIVERAT schema utan dagar och utan kompletta
// tider gav tidigare ett tomt uttryck, så regeln renderades helt utan
// tidsbegränsning — den gällde dygnet runt, tvärtemot avsikten.
func TestEmptyEnabledScheduleSkipsRule(t *testing.T) {
	cfg := baseCfg()
	cfg.Policies = []config.Policy{{
		ID: "p1", Name: "Schemalagd", Enabled: true, Action: config.ActionAccept,
		Service: "TCP:80", SourceZone: "LAN", DestZone: "WAN",
		Schedule: &config.PolicySchedule{Enabled: true}, // inga dagar, inga tider
	}}
	for _, r := range renderRules(t, cfg) {
		if strings.Contains(r.Comment, "Schemalagd") {
			t.Fatalf("regel med tomt men aktiverat schema renderades ändå: %s", exprJSON(t, r))
		}
	}

	// Med ett komplett schema SKA regeln finnas.
	cfg.Policies[0].Schedule = &config.PolicySchedule{Enabled: true, Days: []string{"Monday"}}
	ok := false
	for _, r := range renderRules(t, cfg) {
		if strings.Contains(r.Comment, "Schemalagd") {
			ok = true
		}
	}
	if !ok {
		t.Fatal("regel med giltigt schema renderades inte")
	}
}
