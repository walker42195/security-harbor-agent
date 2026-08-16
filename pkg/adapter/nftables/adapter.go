package nftables

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

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

	// Input 4: Tillåt SSH (port 22) och Management API (port 8443) ENDAST på LAN/VLAN-gränssnitt
	for _, lanDev := range lanDevices {
		// SSH
		root.Nftables = append(root.Nftables, NFTElement{
			Rule: &Rule{
				Family: a.family,
				Table:  a.tableName,
				Chain:  "input",
				Comment: fmt.Sprintf("Allow SSH on LAN %s", lanDev),
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
							"right": 22,
						},
					},
					map[string]interface{}{"accept": nil},
				},
			},
		})

		// Management API
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
		if !pol.Enabled {
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

		rule := &Rule{
			Family:  a.family,
			Table:   a.tableName,
			Chain:   "forward",
			Comment: pol.Name,
		}

		if pol.Action == config.ActionAccept {
			rule.Expr = append(rule.Expr, map[string]interface{}{"accept": nil})
			root.Nftables = append(root.Nftables, NFTElement{Rule: rule})
		} else if pol.Action == config.ActionDrop {
			rule.Expr = append(rule.Expr, map[string]interface{}{"drop": nil})
			root.Nftables = append(root.Nftables, NFTElement{Rule: rule})
		}
	}

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
								"addr": pol.NAT.InternalIP,
								"port": pol.NAT.InternalPort,
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
