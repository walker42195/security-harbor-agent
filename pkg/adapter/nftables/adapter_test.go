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
