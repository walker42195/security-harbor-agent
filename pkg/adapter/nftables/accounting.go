package nftables

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// AccountingTable är en EGEN tabell, skild från security_harbor.
//
// Skälet: huvudregelsetet renderas med "flush ruleset" vid varje applicering,
// vilket nollar alla räknare. Trafikmätningen behöver överleva en
// policyändring — annars nollställs enhetsstatistiken varje gång någon sparar
// en brandväggsregel. Tabellen återskapas därför separat efter varje apply,
// och insamlaren hanterar ändå nollställningar (se pkg/traffic).
const AccountingTable = "security_harbor_acct"

const (
	accountingSetUp   = "up4"   // byte FRÅN enheten (uppladdning)
	accountingSetDown = "down4" // byte TILL enheten (nedladdning)
)

// accountingSetSize är taket för antal samtidigt spårade adresser. Sätts
// generöst men ändligt — en dynamisk mängd utan tak är en minnesläcka i
// kärnan om något oväntat matchar.
const accountingSetSize = 16384

// BuildAccountingRuleset renderar tabellen som mäter trafik per enhet.
//
// Räknarna begränsas till LOKALA nät. Utan den begränsningen hade
// forward-hooken lagt in varje internetvärd som någon pratat med — en
// hemmaanslutning når tiotusentals adresser per dygn, mängden hade slagit i
// taket på kort tid och enhetsstatistiken blivit oläsbar.
//
// Returnerar tom sträng om det inte finns några lokala nät att mäta på; en
// tabell utan begränsning vore sämre än ingen tabell alls.
func BuildAccountingRuleset(cfg *config.Config, family string) string {
	nets := localNetworks(cfg)
	if len(nets) == 0 {
		return ""
	}
	set := "{ " + strings.Join(nets, ", ") + " }"

	var b strings.Builder
	fmt.Fprintf(&b, "table %s %s {\n", family, AccountingTable)
	for _, name := range []string{accountingSetUp, accountingSetDown} {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tsize %d\n\t\tflags dynamic\n\t\ttimeout 24h\n\t}\n",
			name, accountingSetSize)
	}
	// priority -150: före filterkedjorna, så att även trafik som senare
	// stoppas räknas. Det är trafik enheten FAKTISKT genererade, och att den
	// blockerades syns i stället som blockerade anslutningar.
	// policy accept: den här kedjan filtrerar aldrig, den bara räknar.
	b.WriteString("\tchain accounting {\n")
	b.WriteString("\t\ttype filter hook forward priority -150; policy accept;\n")
	fmt.Fprintf(&b, "\t\tip saddr %s update @%s { ip saddr counter }\n", set, accountingSetUp)
	fmt.Fprintf(&b, "\t\tip daddr %s update @%s { ip daddr counter }\n", set, accountingSetDown)
	b.WriteString("\t}\n}\n")
	return b.String()
}

// localNetworks plockar ut CIDR för alla aktiva icke-WAN-gränssnitt.
func localNetworks(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, iface := range cfg.Interfaces {
		if !iface.Enabled || strings.EqualFold(iface.Zone, "WAN") || iface.IPv4 == "" {
			continue
		}
		net := networkOf(iface.IPv4)
		if net == "" || seen[net] {
			continue
		}
		seen[net] = true
		out = append(out, net)
	}
	return out
}

// DeviceCounters är avlästa, KUMULATIVA byte per IP sedan tabellen skapades.
type DeviceCounters struct {
	RxBytes uint64 // nedladdat (till enheten)
	TxBytes uint64 // uppladdat (från enheten)
}

// nftSetListing speglar utdata från `nft -j list table`. Formen är verifierad
// mot nftables 1.1.6:
//
//	"elem": [{"elem": {"val": "10.0.0.5", "expires": 86400,
//	                   "counter": {"packets": 6, "bytes": 504}}}]
//
// Element UTAN timeout/counter serialiseras däremot som ett rått värde, så
// båda formerna måste hanteras.
type nftSetListing struct {
	Nftables []struct {
		Set *struct {
			Name string            `json:"name"`
			Elem []json.RawMessage `json:"elem"`
		} `json:"set"`
	} `json:"nftables"`
}

type nftElemWrapper struct {
	Elem *struct {
		Val     json.RawMessage `json:"val"`
		Counter *struct {
			Bytes uint64 `json:"bytes"`
		} `json:"counter"`
	} `json:"elem"`
}

// ReadAccountingCounters läser av båda mängderna.
func ReadAccountingCounters(ctx context.Context, family string) (map[string]DeviceCounters, error) {
	out, err := exec.CommandContext(ctx, "nft", "-j", "list", "table", family, AccountingTable).Output()
	if err != nil {
		// Tabellen finns inte (ännu) — inget att rapportera, inget fel.
		return map[string]DeviceCounters{}, nil
	}
	var listing nftSetListing
	if err := json.Unmarshal(out, &listing); err != nil {
		return nil, fmt.Errorf("kunde inte tolka nft-utdata: %w", err)
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
			ip, bytes, ok := parseCounterElem(raw)
			if !ok {
				continue
			}
			c := res[ip]
			if isUp {
				c.TxBytes = bytes
			} else {
				c.RxBytes = bytes
			}
			res[ip] = c
		}
	}
	return res, nil
}

func parseCounterElem(raw json.RawMessage) (string, uint64, bool) {
	var w nftElemWrapper
	if err := json.Unmarshal(raw, &w); err != nil || w.Elem == nil || w.Elem.Counter == nil {
		return "", 0, false
	}
	var ip string
	if err := json.Unmarshal(w.Elem.Val, &ip); err != nil {
		return "", 0, false
	}
	return ip, w.Elem.Counter.Bytes, true
}

// ApplyAccounting skapar/uppdaterar tabellen. Anropas efter varje applicering
// av huvudregelsetet, eftersom "flush ruleset" tar bort även den här tabellen.
func ApplyAccounting(ctx context.Context, cfg *config.Config, family string) error {
	ruleset := BuildAccountingRuleset(cfg, family)
	if ruleset == "" {
		return nil
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kunde inte applicera trafikmätning: %w - output: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// networkOf omvandlar "10.0.0.1/24" till nätadressen "10.0.0.0/24".
// Gränssnittets IPv4 anges som värdadress med prefixlängd, men en
// nftables-mängd ska matcha på NÄTET — "10.0.0.1/24" som matchuttryck hade
// nft normaliserat, men vi vill inte förlita oss på det.
func networkOf(cidr string) string {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil || n == nil {
		return ""
	}
	if n.IP.To4() == nil {
		return "" // enbart IPv4 — matchuttrycken nedan är ip saddr/daddr
	}
	return n.String()
}
