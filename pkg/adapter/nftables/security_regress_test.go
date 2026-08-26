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

// multiVlanCfg speglar en verklig installation: ett LAN plus flera VLAN med
// EGNA zoner, däribland ett IoT-nät och en internetexponerad DMZ.
func multiVlanCfg() *config.Config {
	cfg := baseCfg()
	cfg.Zones = append(cfg.Zones,
		config.Zone{Name: "VLAN 9"}, config.Zone{Name: "VLAN 8"}, config.Zone{Name: "VLAN 1337"})
	cfg.Interfaces = append(cfg.Interfaces,
		config.Interface{ID: "vlan9", Device: "ens19.9", Parent: "ens19", VLANID: 9, Zone: "VLAN 9", Enabled: true, IPv4: "10.9.9.1/24"},
		config.Interface{ID: "vlan8", Device: "ens19.8", Parent: "ens19", VLANID: 8, Zone: "VLAN 8", Enabled: true, IPv4: "10.8.8.1/24"},
		config.Interface{ID: "vlan1337", Device: "ens19.1337", Parent: "ens19", VLANID: 1337, Zone: "VLAN 1337", Enabled: true, IPv4: "10.13.13.1/24"},
	)
	cfg.Objects = []config.Object{
		{ID: "obj_admin", Name: "Allowed to Admin", Type: "group", Values: []string{"obj_lan", "obj_vlan9"}},
		{ID: "obj_lan", Name: "VLAN1", Type: "host", Values: []string{"10.0.0.0/24"}},
		{ID: "obj_vlan9", Name: "VLAN9", Type: "host", Values: []string{"10.9.9.0/24"}},
	}
	return cfg
}

func inputRulesFor(t *testing.T, cfg *config.Config, comment string) []Rule {
	t.Helper()
	var out []Rule
	for _, r := range renderRules(t, cfg) {
		if r.Chain == "input" && strings.Contains(r.Comment, comment) {
			out = append(out, r)
		}
	}
	return out
}

// Regression (skarpt 2026-08-26): en LOKAL policy byggdes av enbart
// iifname + schema + tjänst. Varken SourceObj eller SourceZone lästes, så en
// policy som i GUI:t stod som "Från: Allowed to Admin" renderades UTAN
// källbegränsning, på SAMTLIGA interna kort. Management-API:t och SSH var
// därmed nåbara från IoT-VLAN:et och den internetexponerade DMZ:en, trots
// att administratören begränsat dem till två nät.
//
// Exakt samma buggklass rättades för FORWARD-kedjan 2026-08-19; INPUT
// glömdes bort då.
func TestLocalPolicyHonoursSourceObject(t *testing.T) {
	cfg := multiVlanCfg()
	cfg.Policies = []config.Policy{{
		ID: "mgmt", Name: "Management", Enabled: true, Local: true,
		Action: config.ActionAccept, Service: "8443", SourceObj: "obj_admin",
	}}

	rules := inputRulesFor(t, cfg, "Management")
	if len(rules) == 0 {
		t.Fatal("ingen regel renderades alls")
	}
	for _, r := range rules {
		expr := exprJSON(t, r)
		if !strings.Contains(expr, "saddr") {
			t.Errorf("regel utan källbegränsning (%s): %s", r.Comment, expr)
		}
		if !strings.Contains(expr, "10.0.0.0") || !strings.Contains(expr, "10.9.9.0") {
			t.Errorf("objektets nät saknas i regeln (%s): %s", r.Comment, expr)
		}
	}
}

// Zonen ska avgöra VILKA kort regeln läggs på. "LAN" får inte betyda
// "varje internt kort".
func TestLocalPolicyHonoursSourceZone(t *testing.T) {
	cfg := multiVlanCfg()
	cfg.Policies = []config.Policy{{
		ID: "ssh", Name: "SSH", Enabled: true, Local: true,
		Action: config.ActionAccept, Service: "22", SourceZone: "LAN",
	}}

	rules := inputRulesFor(t, cfg, "SSH")
	if len(rules) != 1 {
		var got []string
		for _, r := range rules {
			got = append(got, r.Comment)
		}
		t.Fatalf("förväntade en regel (bara ens19), fick %d: %v", len(rules), got)
	}
	if !strings.Contains(exprJSON(t, rules[0]), "ens19\"") {
		t.Errorf("fel kort: %s", exprJSON(t, rules[0]))
	}
}

// En zon som inte matchar något kort ska inte falla tillbaka på "alla kort".
func TestLocalPolicyUnknownZoneRendersNothing(t *testing.T) {
	cfg := multiVlanCfg()
	cfg.Policies = []config.Policy{{
		ID: "x", Name: "Spökzon", Enabled: true, Local: true,
		Action: config.ActionAccept, Service: "22", SourceZone: "Finns-inte",
	}}
	if rules := inputRulesFor(t, cfg, "Spökzon"); len(rules) != 0 {
		t.Fatalf("policy för okänd zon renderades ändå: %d regler", len(rules))
	}
}

// Ett objekt som inte går att lösa upp (tomt eller borttaget) får ALDRIG bli
// "släpp igenom allt" — det är raka motsatsen till avsikten.
func TestLocalPolicyUnresolvableObjectRendersNothing(t *testing.T) {
	cfg := multiVlanCfg()
	cfg.Policies = []config.Policy{{
		ID: "y", Name: "Trasigt objekt", Enabled: true, Local: true,
		Action: config.ActionAccept, Service: "8443", SourceObj: "obj_finns_inte",
	}}
	if rules := inputRulesFor(t, cfg, "Trasigt objekt"); len(rules) != 0 {
		t.Fatalf("policy med olösbart objekt renderades ändå: %d regler", len(rules))
	}
}

// Utan begränsning ska beteendet vara oförändrat: regeln läggs på alla
// interna kort. Annars hade fixen tyst stängt av fungerande regler.
func TestLocalPolicyWithoutRestrictionCoversAllInternalDevices(t *testing.T) {
	cfg := multiVlanCfg()
	cfg.Policies = []config.Policy{{
		ID: "dns", Name: "Öppen", Enabled: true, Local: true,
		Action: config.ActionAccept, Service: "53", SourceZone: "ANY", SourceObj: "ANY",
	}}
	if rules := inputRulesFor(t, cfg, "Öppen"); len(rules) != 4 {
		t.Fatalf("förväntade fyra kort, fick %d", len(rules))
	}
}

// Samma IP finns nästan garanterat i flera hot-listor. nftables klarar
// dubbletter själv, men agenten ska inte skicka dem i onödan: en
// AbuseIPDB-lista har över 126 000 poster (2026-08-26).
func TestSetElementsAreDeduplicated(t *testing.T) {
	got := cidrsToSetElements([]string{
		"1.2.3.4", "5.6.7.8", "1.2.3.4", "10.0.0.0/24", "10.0.0.0/24", "5.6.7.8",
	})
	if len(got) != 3 {
		t.Fatalf("förväntade 3 unika element, fick %d: %v", len(got), got)
	}
}

// Ordningen måste bevaras, annars ser varje applicering ut som en ändring.
func TestSetElementOrderIsPreserved(t *testing.T) {
	got := cidrsToSetElements([]string{"9.9.9.9", "1.1.1.1", "9.9.9.9", "8.8.8.8"})
	want := []string{"9.9.9.9", "1.1.1.1", "8.8.8.8"}
	if len(got) != len(want) {
		t.Fatalf("fick %v", got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("position %d: fick %v, ville ha %s", i, got[i], w)
		}
	}
}
