package nftables

import (
	"encoding/json"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func TestRenderJSON(t *testing.T) {
	adapter := NewAdapter()

	cfg := &config.Config{
		Version:  1,
		Revision: 1,
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "eth0", Zone: "WAN", Enabled: true},
			{ID: "lan0", Device: "eth1", Zone: "LAN", Enabled: true},
		},
		Policies: []config.Policy{
			{ID: "p1", Name: "Allow LAN to WAN", Enabled: true, Action: config.ActionAccept},
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
		t.Fatalf("Ogiltig JSON genererad: %v", err)
	}

	if len(root.Nftables) == 0 {
		t.Fatalf("Inga nftables-element i genererad JSON")
	}

	// Verifiera att Hård WAN Management block finns i reglerna
	foundWANBlock := false
	for _, el := range root.Nftables {
		if el.Rule != nil && el.Rule.Comment != "" {
			if el.Rule.Comment == "HARD WAN MANAGEMENT BLOCK on eth0" {
				foundWANBlock = true
				break
			}
		}
	}

	if !foundWANBlock {
		t.Errorf("Kritiskt fel: Hård WAN Management-spärr hittades inte i genererad ruleset!")
	}
}
