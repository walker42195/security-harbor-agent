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

	// 2. Basregler för Input chain (Loopback & Stateful + Hård WAN-mgmt-spärr)
	// Input: Loopback accept
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
						"left": map[string]interface{}{"payload": map[string]interface{}{"protocol": "meta", "field": "iifname"}},
						"right": "lo",
					},
				},
				map[string]interface{}{"accept": nil},
			},
		},
	})

	// Input: Established / Related accept
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

	// Input: Hård spärr mot WAN Management API (Rule 3 in Section 3)
	for _, iface := range cfg.Interfaces {
		if iface.Zone == "WAN" && iface.Device != "" {
			root.Nftables = append(root.Nftables, NFTElement{
				Rule: &Rule{
					Family: a.family,
					Table:  a.tableName,
					Chain:  "input",
					Comment: fmt.Sprintf("HARD WAN MANAGEMENT BLOCK on %s", iface.Device),
					Expr: []interface{}{
						map[string]interface{}{
							"match": map[string]interface{}{
								"op": "==",
								"left": map[string]interface{}{"payload": map[string]interface{}{"protocol": "meta", "field": "iifname"}},
								"right": iface.Device,
							},
						},
						map[string]interface{}{
							"match": map[string]interface{}{
								"op": "==",
								"left": map[string]interface{}{"payload": map[string]interface{}{"protocol": "tcp", "field": "dport"}},
								"right": cfg.Settings.APIPort,
							},
						},
						map[string]interface{}{"drop": nil},
					},
				},
			})
		}
	}

	// 3. Forwarding chain: Stateful
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

	// 4. Mappa användar-policies
	for _, pol := range cfg.Policies {
		if !pol.Enabled {
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
