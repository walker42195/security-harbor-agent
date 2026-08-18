package nftables

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// serviceMatchExpr bygger nftables match-uttryck för en Service-sträng, t.ex.
// "ANY", "ICMP", "22", "UDP:53". Delas mellan FORWARD-kedjans policies och
// INPUT-kedjans lokala åtkomstpolicies för att undvika dubblerad parsning.
func serviceMatchExpr(service string) []interface{} {
	svcUpper := strings.ToUpper(strings.TrimSpace(service))
	if svcUpper == "ANY" || svcUpper == "" {
		return nil
	}
	if svcUpper == "ICMP" || svcUpper == "PING" {
		return []interface{}{
			map[string]interface{}{
				"match": map[string]interface{}{
					"op":    "==",
					"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "l4proto"}},
					"right": "icmp",
				},
			},
		}
	}
	if strings.HasPrefix(svcUpper, "UDP") || strings.Contains(svcUpper, "UDP:") {
		portStr := strings.TrimPrefix(svcUpper, "UDP:")
		portStr = strings.TrimSpace(strings.TrimPrefix(portStr, "UDP"))
		if portNum, err := strconv.Atoi(portStr); err == nil && portNum > 0 {
			return []interface{}{
				map[string]interface{}{
					"match": map[string]interface{}{
						"op":    "==",
						"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "udp", "field": "dport"}},
						"right": portNum,
					},
				},
			}
		}
		return []interface{}{
			map[string]interface{}{
				"match": map[string]interface{}{
					"op":    "==",
					"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "l4proto"}},
					"right": "udp",
				},
			},
		}
	}
	// TCP eller rent portnummer
	cleanPort := strings.TrimPrefix(svcUpper, "TCP:")
	cleanPort = strings.TrimSpace(strings.TrimPrefix(cleanPort, "TCP"))
	if portNum, err := strconv.Atoi(cleanPort); err == nil && portNum > 0 {
		return []interface{}{
			map[string]interface{}{
				"match": map[string]interface{}{
					"op":    "==",
					"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "tcp", "field": "dport"}},
					"right": portNum,
				},
			},
		}
	}
	return nil
}

// resolveObjectCIDRs slår upp ett Object-ID mot cfg.Objects och returnerar
// dess konkreta IP/CIDR-lista. "group"-objekt kan innehålla andra objekt-ID:n
// i Values (se kommentaren på config.Object) och löses upp en nivå rekursivt
// — visited förhindrar en oändlig loop om två grupper råkar peka på varandra.
// host/network/iplist/geoip har alla samma form: Values är redan konkreta
// IP/CIDR-strängar (för iplist/geoip fyllda av pkg/threatfeed, Fas 5).
func resolveObjectCIDRs(cfg *config.Config, objID string, visited map[string]bool) []string {
	if objID == "" || strings.EqualFold(objID, "ANY") || visited[objID] {
		return nil
	}
	visited[objID] = true

	for _, obj := range cfg.Objects {
		if obj.ID != objID {
			continue
		}
		if obj.Type != config.ObjectTypeGroup {
			return obj.Values
		}
		var out []string
		for _, memberID := range obj.Values {
			out = append(out, resolveObjectCIDRs(cfg, memberID, visited)...)
		}
		return out
	}
	return nil
}

// objectMatchExpr bygger ett nftables match-uttryck som begränsar en policy
// till trafik vars käll- eller mål-IP finns i det angivna Object:ets
// IP/CIDR-lista (via en anonym mängd, `ip saddr/daddr { ... }`). Returnerar
// (nil, true) om objektet är "ANY" (ingen begränsning ska läggas till), och
// (nil, false) om objektet är satt men löste upp till en TOM lista — det
// senare måste anroparen hantera genom att INTE lägga till en tandlös regel
// (annars matchar "match ingenting" == matcha allt i nftables semantik för
// en tom uttryckslista, vilket är motsatsen till vad en tom hot-lista ska
// betyda).
func objectMatchExpr(cfg *config.Config, objID, field string) (expr []interface{}, isAny bool) {
	if objID == "" || strings.EqualFold(objID, "ANY") {
		return nil, true
	}
	cidrs := resolveObjectCIDRs(cfg, objID, map[string]bool{})
	elements := cidrsToSetElements(cidrs)
	if len(elements) == 0 {
		return nil, false
	}
	return []interface{}{
		map[string]interface{}{
			"match": map[string]interface{}{
				"op":    "==",
				"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "ip", "field": field}},
				"right": map[string]interface{}{"set": elements},
			},
		},
	}, false
}

// cidrsToSetElements omvandlar en lista av IP/CIDR-strängar till nftables
// JSON-mängdelement. En bar CIDR-sträng som "1.2.3.0/24" är INTE giltig
// direkt i "set"-listan — nft -j försöker då tolka den som ett hostnamn att
// DNS-slå upp (`Could not resolve hostname`), upptäckt vid skarp testning
// mot 10.0.0.163 med en riktig Spamhaus DROP-lista (1693 poster) 2026-08-18.
// CIDR-poster måste uttryckas som {"prefix":{"addr":..,"len":..}} — enstaka
// IP-adresser utan "/" fungerar dock fint som råa strängar.
func cidrsToSetElements(cidrs []string) []interface{} {
	var elements []interface{}
	for _, c := range cidrs {
		if !strings.Contains(c, "/") {
			elements = append(elements, c)
			continue
		}
		addr, lenStr, ok := strings.Cut(c, "/")
		length, err := strconv.Atoi(lenStr)
		if !ok || err != nil {
			continue
		}
		elements = append(elements, map[string]interface{}{
			"prefix": map[string]interface{}{"addr": addr, "len": length},
		})
	}
	return elements
}

type Adapter struct {
	tableName string
	family    string
}

func NewAdapter() *Adapter {
	return &Adapter{
		tableName: "security_harbor",
		family:    "inet",
	}
}

// RenderJSON omvandlar en deklarativ Config till nftables JSON-format.
func (a *Adapter) RenderJSON(cfg *config.Config) ([]byte, error) {
	root := JSONRoot{
		Nftables: []NFTElement{
			{Metainfo: &MetaInfo{Version: "1.1.6"}},
			{Flush: &Flush{Ruleset: nil}},
			{Table: &Table{Family: a.family, Name: a.tableName}},
		},
	}

	// 1. Chains
	chains := []Chain{
		{Family: a.family, Table: a.tableName, Name: "input", Type: "filter", Hook: "input", Prio: 0, Policy: "drop"},
		{Family: a.family, Table: a.tableName, Name: "forward", Type: "filter", Hook: "forward", Prio: 0, Policy: "drop"},
		{Family: a.family, Table: a.tableName, Name: "output", Type: "filter", Hook: "output", Prio: 0, Policy: "accept"},
		{Family: a.family, Table: a.tableName, Name: "prerouting", Type: "nat", Hook: "prerouting", Prio: -100},
		{Family: a.family, Table: a.tableName, Name: "postrouting", Type: "nat", Hook: "postrouting", Prio: 100},
	}

	for _, c := range chains {
		ch := c
		root.Nftables = append(root.Nftables, NFTElement{Chain: &ch})
	}

	// Hitta WAN-interfacer och LAN-interfacer
	var wanDevices []string
	var lanDevices []string
	for _, iface := range cfg.Interfaces {
		if !iface.Enabled {
			continue
		}
		if iface.Zone == "WAN" && iface.Device != "" {
			wanDevices = append(wanDevices, iface.Device)
		} else if iface.Device != "" {
			lanDevices = append(lanDevices, iface.Device)
		}
	}

	// 2. INPUT CHAIN
	// Input 1: Loopback accept
	root.Nftables = append(root.Nftables, NFTElement{
		Rule: &Rule{
			Family: a.family,
			Table:  a.tableName,
			Chain:  "input",
			Comment: "Allow loopback interface",
			Expr: []interface{}{
				map[string]interface{}{
					"match": map[string]interface{}{
						"op": "==",
						"left": map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
						"right": "lo",
					},
				},
				map[string]interface{}{"accept": nil},
			},
		},
	})

	// Input 2: Established / Related accept (Stateful)
	root.Nftables = append(root.Nftables, NFTElement{
		Rule: &Rule{
			Family: a.family,
			Table:  a.tableName,
			Chain:  "input",
			Comment: "Allow established/related connections",
			Expr: []interface{}{
				map[string]interface{}{
					"match": map[string]interface{}{
						"op": "in",
						"left": map[string]interface{}{"ct": map[string]interface{}{"key": "state"}},
						"right": []string{"established", "related"},
					},
				},
				map[string]interface{}{"accept": nil},
			},
		},
	})

	// Input 2.5: Tillåt inkommande WireGuard (UDP) på WAN, om aktiverat.
	// Måste ligga FÖRE Input 3 (HARD WAN DROP) annars är VPN:en meningslös.
	if cfg.WireGuard != nil && cfg.WireGuard.Enabled && cfg.WireGuard.ListenPort > 0 {
		for _, wanDev := range wanDevices {
			root.Nftables = append(root.Nftables, NFTElement{
				Rule: &Rule{
					Family:  a.family,
					Table:   a.tableName,
					Chain:   "input",
					Comment: fmt.Sprintf("Allow WireGuard (UDP %d) on WAN %s", cfg.WireGuard.ListenPort, wanDev),
					Expr: []interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"op":    "==",
								"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
								"right": wanDev,
							},
						},
						map[string]interface{}{
							"match": map[string]interface{}{
								"op":    "==",
								"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": "udp", "field": "dport"}},
								"right": cfg.WireGuard.ListenPort,
							},
						},
						map[string]interface{}{"accept": nil},
					},
				},
			})
		}
	}

	// Input 2.6: Tillåt inkommande OpenVPN på WAN, om aktiverat (Fas 4).
	// Måste ligga FÖRE Input 3 (HARD WAN DROP) annars är VPN:en meningslös.
	if cfg.OpenVPN != nil && cfg.OpenVPN.Enabled && cfg.OpenVPN.ListenPort > 0 {
		proto := cfg.OpenVPN.Protocol
		if proto == "" {
			proto = "udp"
		}
		for _, wanDev := range wanDevices {
			root.Nftables = append(root.Nftables, NFTElement{
				Rule: &Rule{
					Family:  a.family,
					Table:   a.tableName,
					Chain:   "input",
					Comment: fmt.Sprintf("Allow OpenVPN (%s %d) on WAN %s", strings.ToUpper(proto), cfg.OpenVPN.ListenPort, wanDev),
					Expr: []interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"op":    "==",
								"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
								"right": wanDev,
							},
						},
						map[string]interface{}{
							"match": map[string]interface{}{
								"op":    "==",
								"left":  map[string]interface{}{"payload": map[string]interface{}{"protocol": proto, "field": "dport"}},
								"right": cfg.OpenVPN.ListenPort,
							},
						},
						map[string]interface{}{"accept": nil},
					},
				},
			})
		}
	}

	// Input 3: HARD WAN DROP ALL INCOMING (Placeras FÖRE alla övriga accept-regler!)
	for _, wanDev := range wanDevices {
		root.Nftables = append(root.Nftables, NFTElement{
			Rule: &Rule{
				Family: a.family,
				Table:  a.tableName,
				Chain:  "input",
				Comment: fmt.Sprintf("HARD WAN DROP ALL INCOMING on %s", wanDev),
				Expr: []interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"op": "==",
							"left": map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
							"right": wanDev,
						},
					},
					map[string]interface{}{"drop": nil},
				},
			},
		})
	}

	// Input 4: Lokala åtkomstpolicies (t.ex. SSH) mot brandväggen själv,
	// ENDAST på LAN/VLAN-gränssnitt. Dessa är vanliga, konfigurerbara
	// Policy-objekt (pol.Local == true) och kan alltså stängas av i GUI:t —
	// se cfg.Policies i store.go för default-policyn "sys-ssh-lan".
	for _, pol := range cfg.Policies {
		if !pol.Local || !pol.Enabled {
			continue
		}
		for _, lanDev := range lanDevices {
			rule := &Rule{
				Family:  a.family,
				Table:   a.tableName,
				Chain:   "input",
				Comment: fmt.Sprintf("%s on LAN %s", pol.Name, lanDev),
				Expr: []interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"op":    "==",
							"left":  map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
							"right": lanDev,
						},
					},
				},
			}
			rule.Expr = append(rule.Expr, serviceMatchExpr(pol.Service)...)
			rule.Expr = append(rule.Expr, map[string]interface{}{"accept": nil})
			root.Nftables = append(root.Nftables, NFTElement{Rule: rule})
		}
	}

	// Management API: alltid nåbar på LAN/VLAN — detta är INTE en
	// konfigurerbar policy (till skillnad från SSH ovan), eftersom det är
	// den enda vägen in i GUI:t. Att kunna stänga av den skulle riskera att
	// låsa ute administratören helt, utan en text-baserad reservväg som SSH.
	for _, lanDev := range lanDevices {
		root.Nftables = append(root.Nftables, NFTElement{
			Rule: &Rule{
				Family: a.family,
				Table:  a.tableName,
				Chain:  "input",
				Comment: fmt.Sprintf("Allow Management API on LAN %s", lanDev),
				Expr: []interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"op": "==",
							"left": map[string]interface{}{"meta": map[string]interface{}{"key": "iifname"}},
							"right": lanDev,
						},
					},
					map[string]interface{}{
						"match": map[string]interface{}{
							"op": "==",
							"left": map[string]interface{}{"payload": map[string]interface{}{"protocol": "tcp", "field": "dport"}},
							"right": cfg.Settings.APIPort,
						},
					},
					map[string]interface{}{"accept": nil},
				},
			},
		})
	}

	// Input 5: Logga och neka allt annat inkommande (synliggör blockerad
	// trafik i GUI:t via /api/v1/diagnostics/firewall-log). Kedjans policy
	// ("drop") är fortfarande fail-safe-spärren om denna regel av någon
	// anledning saknas.
	root.Nftables = append(root.Nftables, NFTElement{
		Rule: &Rule{
			Family:  a.family,
			Table:   a.tableName,
			Chain:   "input",
			Comment: "Log & deny all other input",
			Expr: []interface{}{
				map[string]interface{}{"log": map[string]interface{}{"prefix": "SH-DENY-INPUT: "}},
				map[string]interface{}{"drop": nil},
			},
		},
	})

	// 3. FORWARDING CHAIN (Stateful & Inter-VLAN Policies)
	root.Nftables = append(root.Nftables, NFTElement{
		Rule: &Rule{
			Family: a.family,
			Table:  a.tableName,
			Chain:  "forward",
			Comment: "Allow established/related forwarding",
			Expr: []interface{}{
				map[string]interface{}{
					"match": map[string]interface{}{
						"op": "in",
						"left": map[string]interface{}{"ct": map[string]interface{}{"key": "state"}},
						"right": []string{"established", "related"},
					},
				},
				map[string]interface{}{"accept": nil},
			},
		},
	})

	// Användarpolicies
	for _, pol := range cfg.Policies {
		if !pol.Enabled || pol.Local {
			continue
		}

		// Om detta är en Port Forwarding (DNAT) policy sköts den i prerouting/forward
		if pol.Action == config.ActionDNAT && pol.NAT != nil {
			// Tillåt forwarding till den interna IP-adressen vid DNAT
			root.Nftables = append(root.Nftables, NFTElement{
				Rule: &Rule{
					Family: a.family,
					Table:  a.tableName,
					Chain:  "forward",
					Comment: fmt.Sprintf("Allow DNAT forwarding for %s", pol.Name),
					Expr: []interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"op": "==",
								"left": map[string]interface{}{"payload": map[string]interface{}{"protocol": "ip", "field": "daddr"}},
								"right": pol.NAT.InternalIP,
							},
						},
						map[string]interface{}{"accept": nil},
					},
				},
			})
			continue
		}

		// Käll-/mål-objekt (t.ex. GeoIP-landsblock eller en hot-lista från
		// Spamhaus/Tor, Fas 5): en satt (icke-"ANY") SourceObj/DestObj som
		// löser upp till en TOM lista (källan har inte hämtats än, eller
		// misslyckades) hoppar över hela regeln — annars skulle en trasig
		// hot-lista av misstag matcha ALL trafik (tom uttryckslista i
		// nftables = "matcha allt"), vilket är motsatsen till avsikten.
		srcExpr, srcIsAny := objectMatchExpr(cfg, pol.SourceObj, "saddr")
		if !srcIsAny && srcExpr == nil {
			continue
		}
		dstExpr, dstIsAny := objectMatchExpr(cfg, pol.DestObj, "daddr")
		if !dstIsAny && dstExpr == nil {
			continue
		}

		rule := &Rule{
			Family:  a.family,
			Table:   a.tableName,
			Chain:   "forward",
			Comment: fmt.Sprintf("%s (%s)", pol.Name, pol.Service),
		}

		rule.Expr = append(rule.Expr, srcExpr...)
		rule.Expr = append(rule.Expr, dstExpr...)
		rule.Expr = append(rule.Expr, serviceMatchExpr(pol.Service)...)

		if pol.Action == config.ActionAccept {
			rule.Expr = append(rule.Expr, map[string]interface{}{"accept": nil})
			root.Nftables = append(root.Nftables, NFTElement{Rule: rule})
		} else if pol.Action == config.ActionDrop {
			rule.Expr = append(rule.Expr, map[string]interface{}{"log": map[string]interface{}{"prefix": "SH-DENY-FWD: "}})
			rule.Expr = append(rule.Expr, map[string]interface{}{"drop": nil})
			root.Nftables = append(root.Nftables, NFTElement{Rule: rule})
		}
	}

	// Forward: logga och neka allt annat mellan zoner/VLAN som inte
	// matchade en explicit policy ovan (Default Deny Inter-VLAN, se avsnitt
	// 2.4 i genomförandeplanen), så att det syns i firewall-loggen.
	root.Nftables = append(root.Nftables, NFTElement{
		Rule: &Rule{
			Family:  a.family,
			Table:   a.tableName,
			Chain:   "forward",
			Comment: "Log & deny all other forwarding",
			Expr: []interface{}{
				map[string]interface{}{"log": map[string]interface{}{"prefix": "SH-DENY-FWD: "}},
				map[string]interface{}{"drop": nil},
			},
		},
	})

	// 4. NAT PREROUTING CHAIN (Port Forwarding / DNAT)
	for _, pol := range cfg.Policies {
		if pol.Enabled && pol.Action == config.ActionDNAT && pol.NAT != nil {
			proto := "tcp"
			if pol.NAT.Protocol != "" {
				proto = pol.NAT.Protocol
			}
			root.Nftables = append(root.Nftables, NFTElement{
				Rule: &Rule{
					Family: a.family,
					Table:  a.tableName,
					Chain:  "prerouting",
					Comment: fmt.Sprintf("Port Forwarding (DNAT): %s", pol.Name),
					Expr: []interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"op": "==",
								"left": map[string]interface{}{"payload": map[string]interface{}{"protocol": proto, "field": "dport"}},
								"right": pol.NAT.ExternalPort,
							},
						},
						map[string]interface{}{
							"dnat": map[string]interface{}{
								"family": "ip",
								"addr":   pol.NAT.InternalIP,
								"port":   pol.NAT.InternalPort,
							},
						},
					},
				},
			})
		}
	}

	// 5. NAT POSTROUTING CHAIN (Outbound Masquerade för alla interna nät mot WAN)
	for _, wanDev := range wanDevices {
		root.Nftables = append(root.Nftables, NFTElement{
			Rule: &Rule{
				Family: a.family,
				Table:  a.tableName,
				Chain:  "postrouting",
				Comment: fmt.Sprintf("Outbound NAT Masquerade on %s", wanDev),
				Expr: []interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"op": "==",
							"left": map[string]interface{}{"meta": map[string]interface{}{"key": "oifname"}},
							"right": wanDev,
						},
					},
					map[string]interface{}{"masquerade": nil},
				},
			},
		})
	}

	return json.MarshalIndent(root, "", "  ")
}

// ApplyConfig applicerar eller dry-run validerar en konfiguration.
// Om dryRun == true körs nft -j -c -f - (check mode utan att ändra kärnan).
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, dryRun bool) ([]byte, error) {
	rulesetJSON, err := a.RenderJSON(cfg)
	if err != nil {
		return nil, fmt.Errorf("kunde inte rendera nftables JSON: %w", err)
	}

	args := []string{"-j"}
	if dryRun {
		args = append(args, "-c") // Check / dry-run mode
	}
	args = append(args, "-f", "-")

	cmd := exec.CommandContext(ctx, "nft", args...)
	cmd.Stdin = bytes.NewReader(rulesetJSON)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("nft misslyckades (dryRun=%v): %w - output: %s", dryRun, err, string(out))
	}

	return rulesetJSON, nil
}
