package nftables

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func acctCfg() *config.Config {
	return &config.Config{
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, AddressType: "dhcp", IPv4: "100.73.240.173/19"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, IPv4: "10.0.0.1/24"},
			{ID: "v8", Device: "ens19.8", Zone: "VLAN 8", Enabled: true, IPv4: "10.8.8.1/24"},
			{ID: "off", Device: "ens19.9", Zone: "VLAN 9", Enabled: false, IPv4: "10.9.9.1/24"},
		},
	}
}

func TestAccountingRulesetLimitsToLocalNetworks(t *testing.T) {
	rs := BuildAccountingRuleset(acctCfg(), "inet")

	// Nätadress, inte värdadress.
	if !strings.Contains(rs, "10.0.0.0/24") || !strings.Contains(rs, "10.8.8.0/24") {
		t.Errorf("lokala nät saknas:\n%s", rs)
	}
	if strings.Contains(rs, "10.0.0.1/24") {
		t.Errorf("värdadressen användes i stället för nätadressen:\n%s", rs)
	}
	// WAN får ALDRIG räknas: forward-hooken ser båda riktningarna, så utan
	// begränsning hade varje internetvärd hamnat i mängden och slagit i taket.
	if strings.Contains(rs, "100.73") {
		t.Errorf("WAN-nätet kom med — mängden hade fyllts av internetadresser:\n%s", rs)
	}
	// Avstängda gränssnitt räknas inte.
	if strings.Contains(rs, "10.9.9") {
		t.Errorf("ett avstängt gränssnitt kom med:\n%s", rs)
	}
	// Kedjan får inte filtrera.
	if !strings.Contains(rs, "policy accept") {
		t.Errorf("mätkedjan saknar 'policy accept' — den får aldrig släppa paket:\n%s", rs)
	}
	// Egen tabell, annars nollas räknarna av huvudregelsetets flush ruleset.
	if !strings.Contains(rs, AccountingTable) {
		t.Errorf("fel tabellnamn:\n%s", rs)
	}
	// Dynamiska mängder måste ha ett tak.
	if !strings.Contains(rs, "size ") {
		t.Errorf("mängden saknar storleksgräns — obegränsad dynamisk mängd är en minnesläcka i kärnan:\n%s", rs)
	}
}

func TestAccountingRulesetEmptyWithoutLocalNetworks(t *testing.T) {
	// Bara WAN: hellre ingen mätning alls än en obegränsad mängd.
	cfg := &config.Config{Interfaces: []config.Interface{
		{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, IPv4: "100.73.240.173/19"},
	}}
	if rs := BuildAccountingRuleset(cfg, "inet"); rs != "" {
		t.Errorf("förväntade tom sträng, fick:\n%s", rs)
	}
	if rs := BuildAccountingRuleset(nil, "inet"); rs != "" {
		t.Errorf("nil-config gav en regeluppsättning:\n%s", rs)
	}
}

// Formen är verifierad mot nftables 1.1.6 i en egen nätverksnamnrymd.
const sampleSetJSON = `{"nftables":[
 {"metainfo":{"version":"1.1.6"}},
 {"set":{"family":"inet","name":"up4","table":"security_harbor_acct","elem":[
   {"elem":{"val":"10.0.0.5","expires":86400,"counter":{"packets":6,"bytes":504}}},
   {"elem":{"val":"10.8.8.7","expires":86400,"counter":{"packets":1,"bytes":100}}}]}},
 {"set":{"family":"inet","name":"down4","table":"security_harbor_acct","elem":[
   {"elem":{"val":"10.0.0.5","expires":86400,"counter":{"packets":9,"bytes":9000}}},
   {"elem":{"val":"10.0.0.9","expires":86400}}]}},
 {"set":{"family":"inet","name":"nagot_annat","elem":[
   {"elem":{"val":"10.0.0.5","counter":{"packets":1,"bytes":777}}}]}}
]}`

func TestParseAccountingJSON(t *testing.T) {
	var listing nftSetListing
	if err := jsonUnmarshalHelper(sampleSetJSON, &listing); err != nil {
		t.Fatal(err)
	}
	res := map[string]DeviceCounters{}
	for _, el := range listing.Nftables {
		if el.Set == nil {
			continue
		}
		isUp := el.Set.Name == accountingSetUp
		isDown := el.Set.Name == accountingSetDown
		if !isUp && !isDown {
			continue
		}
		for _, raw := range el.Set.Elem {
			ip, b, ok := parseCounterElem(raw)
			if !ok {
				continue
			}
			c := res[ip]
			if isUp {
				c.TxBytes = b
			} else {
				c.RxBytes = b
			}
			res[ip] = c
		}
	}

	if got := res["10.0.0.5"]; got.TxBytes != 504 || got.RxBytes != 9000 {
		t.Errorf("10.0.0.5 = tx %d / rx %d, ville ha 504 / 9000", got.TxBytes, got.RxBytes)
	}
	if got := res["10.8.8.7"]; got.TxBytes != 100 {
		t.Errorf("10.8.8.7 tx = %d, ville ha 100", got.TxBytes)
	}
	// Element utan counter ska hoppas över, inte ge en nollpost.
	if _, ok := res["10.0.0.9"]; ok {
		t.Error("ett element utan counter togs med")
	}
	// Andra mängder i samma tabell får inte blandas in.
	if res["10.0.0.5"].TxBytes == 777 || res["10.0.0.5"].RxBytes == 777 {
		t.Error("en orelaterad mängd lästes som trafikdata")
	}
}

func jsonUnmarshalHelper(s string, v any) error { return json.Unmarshal([]byte(s), v) }
