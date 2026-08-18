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
