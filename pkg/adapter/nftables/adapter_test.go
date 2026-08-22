package nftables

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func TestRenderJSONFas2(t *testing.T) {
	adapter := NewAdapter()

	cfg := &config.Config{
		Version:  1,
		Revision: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.163/24"},
			{ID: "vlan10", Device: "ens19.10", Parent: "ens19", VLANID: 10, Zone: "SERVERS", Enabled: true, AddressType: "static", IPv4: "192.168.10.1/24"},
		},
		Policies: []config.Policy{
			{
				ID:       "pol1",
				Name:     "Web Server DNAT",
				Enabled:  true,
				Action:   config.ActionDNAT,
				NAT: &config.NATConfig{
					Protocol:     "tcp",
					ExternalPort: 443,
					InternalIP:   "192.168.10.10",
					InternalPort: 443,
				},
			},
		},
		Settings: config.Settings{
			APIPort: 8443,
		},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}

	var root JSONRoot
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("Ogiltig JSON: %v", err)
	}

	// Verifiera att Masquerade och DNAT finns med
	hasMasquerade := false
	hasDNAT := false

	for _, el := range root.Nftables {
		if el.Rule != nil {
			if el.Rule.Chain == "postrouting" {
				hasMasquerade = true
			}
			if el.Rule.Chain == "prerouting" {
				hasDNAT = true
			}
		}
	}

	if !hasMasquerade {
		t.Errorf("Krävde Masquerade-regel i postrouting för WAN ens18, men saknas")
	}
	if !hasDNAT {
		t.Errorf("Krävde DNAT-regel i prerouting för Port 443, men saknas")
	}
}

// TestRenderJSONHooksChainsWithPriority skyddar mot en regression där Chain.Prio
// hade `json:"prio,omitempty"`. Priority 0 (standard för filter-hooks) är
// Go:s int-nollvärde, så omitempty tog tyst bort "prio" ur JSON:en helt —
// och `nft -j` skapar då en kedja som INTE hookas in i netfilter (varken fel
// eller varning). Upptäckt vid skarp testning 2026-08-17: INPUT/FORWARD-
// filtreringen var därför aldrig faktiskt aktiv. Testet läser den RÅA JSON:en
// (inte den avkodade Chain-structen) eftersom json.Unmarshal inte kan
// skilja "fältet saknades" från "fältet var 0".
func TestRenderJSONHooksChainsWithPriority(t *testing.T) {
	adapter := NewAdapter()

	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.163/24"},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}

	var raw struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Ogiltig JSON: %v", err)
	}

	checkedHookChains := map[string]bool{"input": false, "forward": false, "output": false}
	for _, el := range raw.Nftables {
		chainRaw, ok := el["chain"]
		if !ok {
			continue
		}
		var chain map[string]json.RawMessage
		if err := json.Unmarshal(chainRaw, &chain); err != nil {
			t.Fatalf("Ogiltig chain-JSON: %v", err)
		}
		var name string
		_ = json.Unmarshal(chain["name"], &name)
		if _, want := checkedHookChains[name]; !want {
			continue
		}
		if _, hasHook := chain["hook"]; !hasHook {
			continue // t.ex. inte relevant om kedjan av någon anledning saknar hook
		}
		if _, hasPrio := chain["prio"]; !hasPrio {
			t.Errorf("Kedjan %q saknar \"prio\" i JSON-utdatan trots att den har \"hook\" satt — nft -j skapar då en ohookad, overksam kedja", name)
		}
		checkedHookChains[name] = true
	}

	for name, checked := range checkedHookChains {
		if !checked {
			t.Errorf("Hittade aldrig en hookad %q-kedja att verifiera \"prio\" på", name)
		}
	}
}

func TestRenderJSONWireGuardWANAllow(t *testing.T) {
	adapter := NewAdapter()

	cfg := &config.Config{
		Version:  1,
		Revision: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.163/24"},
		},
		WireGuard: &config.WireGuardConfig{
			Enabled:    true,
			ListenPort: 51820,
			Address:    "10.66.66.1/24",
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}

	var root JSONRoot
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("Ogiltig JSON: %v", err)
	}

	dropIdx, allowIdx := -1, -1
	for i, el := range root.Nftables {
		if el.Rule == nil || el.Rule.Chain != "input" {
			continue
		}
		if strings.Contains(el.Rule.Comment, "HARD WAN DROP") {
			dropIdx = i
		}
		if strings.Contains(el.Rule.Comment, "Allow WireGuard") {
			allowIdx = i
		}
	}

	if allowIdx == -1 {
		t.Fatalf("Krävde en WAN-allow-regel för WireGuard (UDP 51820), men saknas")
	}
	if dropIdx == -1 {
		t.Fatalf("Krävde HARD WAN DROP-regeln, men saknas")
	}
	if allowIdx > dropIdx {
		t.Errorf("WireGuard-allow-regeln måste ligga FÖRE HARD WAN DROP (index %d > %d), annars är porten meningslös", allowIdx, dropIdx)
	}
}

// TestRenderJSONPolicyObjectMatching skyddar mot en regression där
// Policy.SourceObj/DestObj (t.ex. en GeoIP- eller hot-lista, Fas 5) tyst
// ignorerades av nftables-adaptern — policyn genererade en regel som
// matchade ALL trafik för tjänsten, oavsett vilket objekt som var valt i
// GUI:t. Upptäckt vid kodgranskning 2026-08-18 (dokumenterat som öppet fynd
// redan i Fas 3-rapporten). Testar både att en satt SourceObj faktiskt
// begränsar regeln till dess IP-lista, och att en SourceObj som pekar på
// ett objekt med en TOM Values-lista (t.ex. en hot-lista som ännu inte
// hunnit hämtas) hoppar över regeln helt — annars skulle en tom
// uttryckslista i nftables betyda "matcha allt", raka motsatsen till avsikt.
func TestRenderJSONPolicyObjectMatching(t *testing.T) {
	adapter := NewAdapter()

	baseCfg := func(objects []config.Object) *config.Config {
		return &config.Config{
			Version: 1,
			Interfaces: []config.Interface{
				{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
				{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.163/24"},
			},
			Objects: objects,
			Policies: []config.Policy{
				{
					ID: "pol-block-hotlist", Name: "Block Spamhaus", Enabled: true,
					SourceObj: "hotlist1", DestObj: "ANY", Service: "ANY", Action: config.ActionDrop,
				},
			},
			Settings: config.Settings{APIPort: 8443},
		}
	}

	t.Run("SourceObj med värden begränsar regeln", func(t *testing.T) {
		cfg := baseCfg([]config.Object{
			{ID: "hotlist1", Name: "Spamhaus DROP", Type: config.ObjectTypeIPList, Values: []string{"1.2.3.0/24", "5.6.7.8/32"}},
		})
		data, err := adapter.RenderJSON(cfg)
		if err != nil {
			t.Fatalf("RenderJSON misslyckades: %v", err)
		}
		// CIDR-poster måste vara strukturerade {"prefix":{"addr":..,"len":..}}
		// i JSON:en, inte bara-strängen "1.2.3.0/24" — nft -j tolkar annars
		// bar-strängen som ett hostnamn att DNS-slå upp och avvisar hela
		// regeln (upptäckt vid skarp testning 2026-08-18).
		if !strings.Contains(string(data), `"addr": "1.2.3.0"`) || !strings.Contains(string(data), `"len": 24`) {
			t.Errorf("förväntade en strukturerad prefix-post för 1.2.3.0/24 i den genererade JSON-regeln, men den saknas: %s", string(data))
		}
		if strings.Contains(string(data), `"1.2.3.0/24"`) {
			t.Errorf("hittade CIDR som en RÅ STRÄNG i set-elementen — nft -j avvisar det med \"Could not resolve hostname\": %s", string(data))
		}
		if !strings.Contains(string(data), `"addr": "5.6.7.8"`) {
			t.Errorf("förväntade en strukturerad prefix-post för 5.6.7.8/32 i den genererade JSON-regeln, men den saknas: %s", string(data))
		}
	})

	t.Run("SourceObj med tom lista hoppar över regeln", func(t *testing.T) {
		cfg := baseCfg([]config.Object{
			{ID: "hotlist1", Name: "Spamhaus DROP", Type: config.ObjectTypeIPList, Values: []string{}},
		})
		data, err := adapter.RenderJSON(cfg)
		if err != nil {
			t.Fatalf("RenderJSON misslyckades: %v", err)
		}
		if strings.Contains(string(data), "Block Spamhaus") {
			t.Errorf("en SourceObj som löser till en TOM lista fick ändå en genererad regel — det skulle matcha ALL trafik: %s", string(data))
		}
	})
}

// TestRenderJSONPolicySchedule verifierar att en tidsstyrd policy (Fas 7)
// genererar `meta day`/`meta hour`-matchningar, med samma JSON-form som
// verifierades manuellt mot skarp `nft -c -j` 2026-08-18 (meta day kräver
// en mängd av veckodagsnamn, inte en bar array/bitmask).
// TestRenderJSONDNSAllowOnLAN verifierar att DNS (UDP+TCP 53) tillåts till
// brandväggen själv från LAN när DNS.Enabled är satt (Fas 6), och att den
// INTE finns med när DNS är avstängt.
func TestRenderJSONDNSAllowOnLAN(t *testing.T) {
	adapter := NewAdapter()
	baseCfg := func(dnsEnabled bool) *config.Config {
		var d *config.DNSConfig
		if dnsEnabled {
			d = &config.DNSConfig{Enabled: true, UpstreamServers: []string{"1.1.1.1"}}
		}
		return &config.Config{
			Version: 1,
			Interfaces: []config.Interface{
				{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
				{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.163/24"},
			},
			DNS:      d,
			Settings: config.Settings{APIPort: 8443},
		}
	}

	data, err := adapter.RenderJSON(baseCfg(true))
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}
	if !strings.Contains(string(data), "Allow DNS (UDP 53) on LAN ens19") || !strings.Contains(string(data), "Allow DNS (TCP 53) on LAN ens19") {
		t.Errorf("förväntade DNS-allow-regler för både UDP och TCP på LAN, men saknas: %s", string(data))
	}

	data2, err := adapter.RenderJSON(baseCfg(false))
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}
	if strings.Contains(string(data2), "Allow DNS") {
		t.Errorf("DNS-allow-regler ska inte finnas när DNS.Enabled är false: %s", string(data2))
	}
}

func TestRenderJSONPolicySchedule(t *testing.T) {
	adapter := NewAdapter()
	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.163/24"},
		},
		Policies: []config.Policy{
			{
				ID: "pol-schedule", Name: "Office Hours Only", Enabled: true,
				SourceObj: "ANY", DestObj: "ANY", Service: "ANY", Action: config.ActionAccept,
				Schedule: &config.PolicySchedule{Enabled: true, Days: []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}, StartTime: "08:00", EndTime: "17:00"},
			},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, `"key": "day"`) || !strings.Contains(s, `"Monday"`) {
		t.Errorf("förväntade en meta-day-matchning med veckodagar, men saknas: %s", s)
	}
	if !strings.Contains(s, `"key": "hour"`) || !strings.Contains(s, `"08:00"`) || !strings.Contains(s, `"17:00"`) {
		t.Errorf("förväntade en meta-hour-range-matchning, men saknas: %s", s)
	}
}

// TestRenderJSONLogPrefixesCarryPolicyName skyddar attributionen i
// loggningsvyn (GUI:t ska kunna visa VILKEN regel som tillät/nekade
// trafiken, inte bara att den gjorde det) — verifierar att både
// accept- och drop-policies får ett unikt, policynamn-bärande
// `log prefix`, att default-deny-fallbacken har ett fast namn, och att
// ett ":" i policynamnet saneras bort (annars blir log-prefixets
// "SH-ACTION-CHAIN-NAMN:"-gräns tvetydig för parseFirewallLog).
func TestRenderJSONLogPrefixesCarryPolicyName(t *testing.T) {
	adapter := NewAdapter()
	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.163/24"},
		},
		Policies: []config.Policy{
			{ID: "pol-allow", Name: "Kontor: Internet", Enabled: true, SourceObj: "ANY", DestObj: "ANY", Service: "ANY", Action: config.ActionAccept},
			{ID: "pol-deny", Name: "Block IoT", Enabled: true, SourceObj: "ANY", DestObj: "ANY", Service: "ANY", Action: config.ActionDrop},
			{ID: "pol-ssh", Name: "SSH Admin", Enabled: true, Local: true, Service: "22"},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}
	s := string(data)

	if !strings.Contains(s, `SH-ACCEPT-FWD-Kontor- Internet: `) {
		t.Errorf("förväntade ett SH-ACCEPT-FWD-prefix med policynamnet (\":\" saneras till \"-\"), men saknas: %s", s)
	}
	if !strings.Contains(s, `SH-DENY-FWD-Block IoT: `) {
		t.Errorf("förväntade ett SH-DENY-FWD-prefix med policynamnet, men saknas: %s", s)
	}
	if !strings.Contains(s, `SH-ACCEPT-INPUT-SSH Admin: `) {
		t.Errorf("förväntade ett SH-ACCEPT-INPUT-prefix för den lokala SSH-policyn, men saknas: %s", s)
	}
	if !strings.Contains(s, `SH-DENY-FWD-DefaultDeny: `) {
		t.Errorf("förväntade ett fast namngivet default-deny-prefix i forward-kedjan, men saknas: %s", s)
	}
	if !strings.Contains(s, `SH-DENY-INPUT-DefaultDeny: `) {
		t.Errorf("förväntade ett fast namngivet default-deny-prefix i input-kedjan, men saknas: %s", s)
	}
}

// TestRenderJSONServiceGroupExpandsToMultipleRules verifierar att en
// Policy vars Service pekar på en Service Group (Fas 7) genererar EN
// regel PER medlem (nftables kan inte uttrycka "ELLER" mellan orelaterade
// match-satser i en enda regel).
func TestRenderJSONServiceGroupExpandsToMultipleRules(t *testing.T) {
	adapter := NewAdapter()
	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.163/24"},
		},
		Services: []config.Service{
			{ID: "svc-http", Name: "HTTP", Protocol: "tcp", Ports: []string{"80"}},
			{ID: "svc-https", Name: "HTTPS", Protocol: "tcp", Ports: []string{"443"}},
			{ID: "svc-web", Name: "Web", Protocol: "group", Members: []string{"svc-http", "svc-https"}},
		},
		Policies: []config.Policy{
			{ID: "pol-web", Name: "Allow Web", Enabled: true, SourceObj: "ANY", DestObj: "ANY", Service: "svc-web", Action: config.ActionAccept},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}

	var root JSONRoot
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("Ogiltig JSON: %v", err)
	}

	found80, found443 := false, false
	for _, el := range root.Nftables {
		if el.Rule == nil || el.Rule.Chain != "forward" || el.Rule.Comment != "Allow Web (svc-web)" {
			continue
		}
		s, _ := json.Marshal(el.Rule.Expr)
		if strings.Contains(string(s), "80") {
			found80 = true
		}
		if strings.Contains(string(s), "443") {
			found443 = true
		}
	}
	if !found80 || !found443 {
		t.Errorf("förväntade separata regler för både port 80 och 443 (gruppens medlemmar), fick found80=%v found443=%v", found80, found443)
	}
}

// TestRenderJSONSNATOverrideBeforeMasquerade verifierar att en Fas 7
// SNAT-override-policy renderas FÖRE den generella masquerade-regeln i
// postrouting-kedjan — nftables nat-kedjor applicerar bara EN nat-åtgärd
// per anslutning (första matchande regeln), så ordningen är avgörande.
func TestRenderJSONSNATOverrideBeforeMasquerade(t *testing.T) {
	adapter := NewAdapter()
	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.163/24"},
		},
		Objects: []config.Object{
			{ID: "obj-server", Name: "Special Server", Type: config.ObjectTypeHost, Values: []string{"192.168.10.50/32"}},
		},
		Policies: []config.Policy{
			{
				ID: "pol-snat", Name: "Custom Egress IP", Enabled: true, Action: config.ActionSNAT,
				SourceObj: "obj-server", DestObj: "ANY",
				NAT: &config.NATConfig{ExternalIP: "203.0.113.9"},
			},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}

	var root JSONRoot
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("Ogiltig JSON: %v", err)
	}

	snatIdx, masqIdx := -1, -1
	for i, el := range root.Nftables {
		if el.Rule == nil || el.Rule.Chain != "postrouting" {
			continue
		}
		if strings.Contains(el.Rule.Comment, "SNAT override") {
			snatIdx = i
		}
		if strings.Contains(el.Rule.Comment, "Masquerade") {
			masqIdx = i
		}
	}
	if snatIdx == -1 {
		t.Fatalf("hittade ingen SNAT-override-regel i postrouting")
	}
	if masqIdx == -1 {
		t.Fatalf("hittade ingen masquerade-regel i postrouting")
	}
	if snatIdx > masqIdx {
		t.Errorf("SNAT-override måste komma FÖRE masquerade-regeln (index %d > %d), annars vinner masquerade alltid", snatIdx, masqIdx)
	}
}

func TestRenderJSONOpenVPNWANAllow(t *testing.T) {
	adapter := NewAdapter()

	cfg := &config.Config{
		Version:  1,
		Revision: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.163/24"},
		},
		OpenVPN: &config.OpenVPNConfig{
			Enabled:    true,
			ListenPort: 1194,
			Protocol:   "udp",
			Address:    "10.77.77.0/24",
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}

	var root JSONRoot
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("Ogiltig JSON: %v", err)
	}

	dropIdx, allowIdx := -1, -1
	for i, el := range root.Nftables {
		if el.Rule == nil || el.Rule.Chain != "input" {
			continue
		}
		if strings.Contains(el.Rule.Comment, "HARD WAN DROP") {
			dropIdx = i
		}
		if strings.Contains(el.Rule.Comment, "Allow OpenVPN") {
			allowIdx = i
		}
	}

	if allowIdx == -1 {
		t.Fatalf("Krävde en WAN-allow-regel för OpenVPN (UDP 1194), men saknas")
	}
	if dropIdx == -1 {
		t.Fatalf("Krävde HARD WAN DROP-regeln, men saknas")
	}
	if allowIdx > dropIdx {
		t.Errorf("OpenVPN-allow-regeln måste ligga FÖRE HARD WAN DROP (index %d > %d), annars är porten meningslös", allowIdx, dropIdx)
	}
}

// TestRenderJSONHostModeSkipsForwardAndNAT verifierar Fas 13:s
// enkelkorts-/värddator-läge — inga forward/nat-kedjor eller -regler ska
// genereras alls, men INPUT-kedjan (inkl. en lokal accept-policy) ska
// fortfarande fungera precis som i gateway-läge.
func TestRenderJSONHostModeSkipsForwardAndNAT(t *testing.T) {
	adapter := NewAdapter()

	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "eth0", Device: "eth0", Zone: "HOST", Enabled: true, AddressType: "dhcp"},
		},
		Policies: []config.Policy{
			{ID: "ssh", Name: "SSH Admin", Enabled: true, Local: true, Action: config.ActionAccept, Service: "22"},
		},
		Settings: config.Settings{APIPort: 8443, Mode: config.ModeHost},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}

	var root JSONRoot
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("Ogiltig JSON: %v", err)
	}

	sawInput, sawForward, sawNAT := false, false, false
	for _, el := range root.Nftables {
		if el.Chain != nil {
			switch el.Chain.Name {
			case "input":
				sawInput = true
			case "forward":
				sawForward = true
			case "prerouting", "postrouting":
				sawNAT = true
			}
		}
		if el.Rule != nil {
			switch el.Rule.Chain {
			case "forward":
				sawForward = true
			case "prerouting", "postrouting":
				sawNAT = true
			}
		}
	}

	if !sawInput {
		t.Error("förväntade en input-kedja i host-läge, saknas")
	}
	if sawForward {
		t.Error("förväntade INGEN forward-kedja/regel i host-läge, men hittade en")
	}
	if sawNAT {
		t.Error("förväntade INGA nat-kedjor/regler (prerouting/postrouting) i host-läge, men hittade en")
	}
}

// TestRenderJSONGatewayModeStillHasForwardAndNAT skyddar mot att
// host-läges-avgränsningen av misstag också slår av forward/nat i det
// vanliga (gateway) läget — bakåtkompatibilitet.
func TestRenderJSONGatewayModeStillHasForwardAndNAT(t *testing.T) {
	adapter := NewAdapter()

	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.1/24"},
		},
		Settings: config.Settings{APIPort: 8443}, // Mode ospecificerat = gateway
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}

	var root JSONRoot
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("Ogiltig JSON: %v", err)
	}

	sawForwardChain, sawNATChain := false, false
	for _, el := range root.Nftables {
		if el.Chain != nil && el.Chain.Name == "forward" {
			sawForwardChain = true
		}
		if el.Chain != nil && (el.Chain.Name == "prerouting" || el.Chain.Name == "postrouting") {
			sawNATChain = true
		}
	}
	if !sawForwardChain {
		t.Error("förväntade forward-kedjan i gateway-läge (tomt Mode-fält), men saknas")
	}
	if !sawNATChain {
		t.Error("förväntade nat-kedjorna i gateway-läge (tomt Mode-fält), men saknas")
	}
}

// TestRenderJSONZoneRestrictsForwardTraffic skyddar mot en riktig
// säkerhetslucka hittad 2026-08-19: SourceZone/DestZone sattes av GUI:t
// men lästes ALDRIG av FORWARD-kedjans regelgenerering — en zon-begränsad
// policy utan ett valt objekt blev i praktiken en ANY-till-ANY-regel.
func TestRenderJSONZoneRestrictsForwardTraffic(t *testing.T) {
	adapter := NewAdapter()

	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.1/24"},
			{ID: "srv0", Device: "ens19.10", Parent: "ens19", VLANID: 10, Zone: "SERVERS", Enabled: true, AddressType: "static", IPv4: "10.0.10.1/24"},
		},
		Policies: []config.Policy{
			{
				ID: "pol-servers-to-lan", Name: "Servers till LAN RDP", Enabled: true,
				SourceZone: "SERVERS", DestZone: "LAN", SourceObj: "ANY", DestObj: "ANY",
				Service: "RDP", Action: config.ActionAccept,
			},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}
	s := string(data)

	if !strings.Contains(s, `"iifname"`) || !strings.Contains(s, `"ens19.10"`) {
		t.Errorf("förväntade en iifname-matchning mot SERVERS-zonens gränssnitt (ens19.10), men saknas: %s", s)
	}
	if !strings.Contains(s, `"oifname"`) || !strings.Contains(s, `"ens19"`) {
		t.Errorf("förväntade en oifname-matchning mot LAN-zonens gränssnitt (ens19), men saknas: %s", s)
	}
}

// TestRenderJSONZoneWithNoMatchingInterfaceSkipsRule speglar
// TestRenderJSONPolicyObjectMatching/tom-lista-fallet: en zon som inte
// matchar något aktiverat gränssnitt (t.ex. en felstavning) ska hoppa
// över regeln helt, INTE bli en matcha-allt-regel.
func TestRenderJSONZoneWithNoMatchingInterfaceSkipsRule(t *testing.T) {
	adapter := NewAdapter()

	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.1/24"},
		},
		Policies: []config.Policy{
			{
				ID: "pol-typo-zone", Name: "Felstavad zon-policy", Enabled: true,
				SourceZone: "SERVRAR", DestZone: "ANY", SourceObj: "ANY", DestObj: "ANY",
				Service: "ANY", Action: config.ActionAccept,
			},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}
	if strings.Contains(string(data), "Felstavad zon-policy") {
		t.Errorf("en SourceZone som inte matchar något gränssnitt fick ändå en genererad regel — det skulle matcha ALL trafik: %s", string(data))
	}
}

// TestRenderJSONZoneAnyIsUnrestricted är ett regressionsskydd: en policy
// utan zon-begränsning (SourceZone/DestZone tomt eller "ANY", som alla
// befintliga tester i den här filen redan använder) ska fortsätta fungera
// precis som innan zoneMatchExpr fanns.
func TestRenderJSONZoneAnyIsUnrestricted(t *testing.T) {
	adapter := NewAdapter()

	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.1/24"},
		},
		Policies: []config.Policy{
			{
				ID: "pol-any-zone", Name: "Ingen zonbegränsning", Enabled: true,
				SourceZone: "ANY", DestZone: "", SourceObj: "ANY", DestObj: "ANY",
				Service: "ANY", Action: config.ActionAccept,
			},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}
	if !strings.Contains(string(data), "Ingen zonbegränsning") {
		t.Errorf("en policy med SourceZone=ANY/tomt DestZone ska fortfarande generera en regel: %s", string(data))
	}
}

// TestRenderJSONLocalPolicyHonorsDropAction skyddar mot en bugg där
// INPUT-kedjans loop för lokala policies alltid la till {"accept": nil}
// utan att titta på pol.Action — en lokal regel som administratören satt
// till "Denied (Drop)" i GUI:t renderades då som en ACCEPT-regel, alltså
// raka motsatsen till vad GUI:t visade.
func TestRenderJSONLocalPolicyHonorsDropAction(t *testing.T) {
	adapter := NewAdapter()
	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.1/24"},
		},
		Policies: []config.Policy{
			{ID: "pol-ssh-deny", Name: "Blockera SSH", Enabled: true, Local: true, Service: "22", Action: config.ActionDrop},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, `SH-DENY-INPUT-Blockera SSH: `) {
		t.Errorf("en lokal drop-policy ska ge ett SH-DENY-INPUT-prefix, inte ett accept-prefix: %s", s)
	}
	if strings.Contains(s, `SH-ACCEPT-INPUT-Blockera SSH: `) {
		t.Errorf("en lokal drop-policy renderades som ACCEPT — det är just buggen testet skyddar mot: %s", s)
	}
}

// TestRenderJSONRejectActionGeneratesRule: config.ActionReject föll
// tidigare igenom FORWARD-kedjans if/else-if utan att generera NÅGON
// regel alls, dvs den var tyst verkningslös.
func TestRenderJSONRejectActionGeneratesRule(t *testing.T) {
	adapter := NewAdapter()
	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.1/24"},
		},
		Policies: []config.Policy{
			{ID: "pol-rej", Name: "Neka med svar", Enabled: true, SourceObj: "ANY", DestObj: "ANY", Service: "ANY", Action: config.ActionReject},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "Neka med svar") || !strings.Contains(s, `"reject"`) {
		t.Errorf("en reject-policy ska generera en regel med ett reject-verdikt: %s", s)
	}
}

// TestRenderJSONDNATForwardIsPortRestricted: följeregeln i FORWARD-kedjan
// matchade tidigare BARA mål-IP:n, vilket öppnade ALLA portar och
// protokoll mot den interna värden istället för bara den vidarebefordrade
// tjänsten.
func TestRenderJSONDNATForwardIsPortRestricted(t *testing.T) {
	adapter := NewAdapter()
	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.1/24"},
		},
		Policies: []config.Policy{
			{
				ID: "pol-dnat", Name: "Webbserver", Enabled: true, Action: config.ActionDNAT,
				NAT: &config.NATConfig{ExternalPort: 443, InternalIP: "192.168.10.10", InternalPort: 8443, Protocol: "tcp"},
			},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}

	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("ogiltig JSON: %v", err)
	}
	elements, _ := root["nftables"].([]interface{})

	found := false
	for _, el := range elements {
		m, _ := el.(map[string]interface{})
		rule, _ := m["rule"].(map[string]interface{})
		if rule == nil || rule["chain"] != "forward" {
			continue
		}
		comment, _ := rule["comment"].(string)
		if !strings.Contains(comment, "Webbserver") {
			continue
		}
		found = true
		exprs, _ := rule["expr"].([]interface{})
		hasPort := false
		for _, e := range exprs {
			em, _ := e.(map[string]interface{})
			match, _ := em["match"].(map[string]interface{})
			if match == nil {
				continue
			}
			left, _ := match["left"].(map[string]interface{})
			payload, _ := left["payload"].(map[string]interface{})
			if payload["field"] == "dport" && payload["protocol"] == "tcp" && match["right"] == float64(8443) {
				hasPort = true
			}
		}
		if !hasPort {
			t.Errorf("DNAT-följeregeln saknar port/protokoll-matchning och öppnar därmed hela den interna värden: %s", string(data))
		}
	}
	if !found {
		t.Fatalf("hittade ingen DNAT-följeregel i forward-kedjan: %s", string(data))
	}
}

// TestRenderJSONDNATHasHairpinMasquerade skyddar NAT-reflektionen: en
// intern klient som via extern DNS ansluter till brandväggens WAN-IP och
// DNAT:as in till en intern server måste få svaret tillbaka. Det kräver en
// postrouting-maskerad som matchar internt ursprung (iifname != WAN) mot
// serverns interna IP:port.
func TestRenderJSONDNATHasHairpinMasquerade(t *testing.T) {
	adapter := NewAdapter()
	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.1/24"},
		},
		Policies: []config.Policy{
			{
				ID: "pol-dnat", Name: "Webbserver", Enabled: true, Action: config.ActionDNAT,
				NAT: &config.NATConfig{ExternalPort: 443, InternalIP: "192.168.10.10", InternalPort: 8443, Protocol: "tcp"},
			},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("ogiltig JSON: %v", err)
	}
	elements, _ := root["nftables"].([]interface{})

	found := false
	for _, el := range elements {
		m, _ := el.(map[string]interface{})
		rule, _ := m["rule"].(map[string]interface{})
		if rule == nil || rule["chain"] != "postrouting" {
			continue
		}
		comment, _ := rule["comment"].(string)
		if !strings.Contains(comment, "hairpin") {
			continue
		}
		found = true
		exprs, _ := rule["expr"].([]interface{})
		hasIifNeq, hasDaddr, hasMasq := false, false, false
		for _, e := range exprs {
			em, _ := e.(map[string]interface{})
			if _, ok := em["masquerade"]; ok {
				hasMasq = true
			}
			match, _ := em["match"].(map[string]interface{})
			if match == nil {
				continue
			}
			if match["op"] == "!=" {
				left, _ := match["left"].(map[string]interface{})
				if meta, _ := left["meta"].(map[string]interface{}); meta != nil && meta["key"] == "iifname" {
					hasIifNeq = true
				}
			}
			left, _ := match["left"].(map[string]interface{})
			if payload, _ := left["payload"].(map[string]interface{}); payload != nil && payload["field"] == "daddr" && match["right"] == "192.168.10.10" {
				hasDaddr = true
			}
		}
		if !hasIifNeq || !hasDaddr || !hasMasq {
			t.Errorf("hairpin-regeln saknar delar (iif!=WAN=%v, daddr=%v, masq=%v): %s", hasIifNeq, hasDaddr, hasMasq, string(data))
		}
	}
	if !found {
		t.Fatalf("hittade ingen NAT-reflektion (hairpin) i postrouting: %s", string(data))
	}
}

// TestRenderJSONUnparseableServiceSkipsRule: en tjänstesträng som inte
// gick att tolka gav tidigare en regel HELT UTAN portbegränsning — en
// accept-regel avsedd för en enda port öppnade då tyst alla portar
// (fail-open). Regeln ska hoppas över istället.
func TestRenderJSONUnparseableServiceSkipsRule(t *testing.T) {
	adapter := NewAdapter()
	cfg := &config.Config{
		Version: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, AddressType: "static", IPv4: "10.0.0.1/24"},
		},
		Policies: []config.Policy{
			{ID: "pol-bad", Name: "Trasig tjänst", Enabled: true, SourceObj: "ANY", DestObj: "ANY", Service: "80,443", Action: config.ActionAccept},
		},
		Settings: config.Settings{APIPort: 8443},
	}

	data, err := adapter.RenderJSON(cfg)
	if err != nil {
		t.Fatalf("RenderJSON misslyckades: %v", err)
	}
	if strings.Contains(string(data), "Trasig tjänst") {
		t.Errorf("en policy med en otolkbar tjänst ska hoppas över, inte bli en regel utan portbegränsning: %s", string(data))
	}
}

// TestServiceMatchExprPortRange: portintervall ska stödjas, och portar
// utanför 1-65535 avvisas (tidigare kollades bara > 0, så 99999 slank
// igenom till nft som ett obegripligt lågnivåfel vid apply).
func TestServiceMatchExprPortRange(t *testing.T) {
	if _, ok := serviceMatchExpr("TCP:8000-8100"); !ok {
		t.Errorf("portintervall TCP:8000-8100 ska kunna tolkas")
	}
	if _, ok := serviceMatchExpr("99999"); ok {
		t.Errorf("port 99999 är utanför giltigt intervall och ska avvisas")
	}
	if _, ok := serviceMatchExpr("0"); ok {
		t.Errorf("port 0 ska avvisas")
	}
	if expr, ok := serviceMatchExpr("ANY"); !ok || expr != nil {
		t.Errorf("ANY ska ge (nil, true) = medvetet ingen begränsning")
	}
}
