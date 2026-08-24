package dhcp

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// TestGenerateKeaConfigIncludesSubnetID skyddar mot en riktig incident
// 2026-08-24: subnet4-posterna saknade helt fältet "id", vilket denna
// Kea-version kräver strikt ("DHCP4_PARSER_FAIL ... subnet configuration
// failed: missing parameter 'id'") — Kea vägrade starta, DHCP var helt
// nere tills bara EN DHCP-aktiverad zon fanns kvar (då maskerades buggen).
func TestGenerateKeaConfigIncludesSubnetID(t *testing.T) {
	a := &Adapter{leaseDBPath: "/tmp/leases.csv"}
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{
				Device: "ens19.9", Zone: "VLAN9", Enabled: true, IPv4: "10.9.9.1/24",
				DHCP: &config.DHCPConfig{Enabled: true, RangeStart: "10.9.9.100", RangeEnd: "10.9.9.199", Gateway: "10.9.9.1"},
			},
			{
				Device: "ens19.1337", Zone: "VLAN1337", Enabled: true, IPv4: "10.13.13.1/24",
				DHCP: &config.DHCPConfig{Enabled: true, RangeStart: "10.13.13.100", RangeEnd: "10.13.13.199", Gateway: "10.13.13.1"},
			},
		},
	}

	data, err := a.GenerateKeaConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateKeaConfig misslyckades: %v", err)
	}

	var parsed KeaConfig
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("kunde inte tolka genererad config: %v", err)
	}
	if len(parsed.Dhcp4.Subnet4) != 2 {
		t.Fatalf("förväntade 2 subnet4-poster, fick %d", len(parsed.Dhcp4.Subnet4))
	}
	seen := map[int]bool{}
	for _, s := range parsed.Dhcp4.Subnet4 {
		if s.ID == 0 {
			t.Errorf("subnet4 för %q saknar id (eller har det ogiltiga värdet 0)", s.Subnet)
		}
		if seen[s.ID] {
			t.Errorf("dubblerat subnet4-id %d", s.ID)
		}
		seen[s.ID] = true
	}
}

// TestGenerateKeaConfigNoDHCPZonesEmitsEmptyArray skyddar mot en riktig
// incident 2026-08-24: när ingen zon hade DHCP aktiverat marshalade
// encoding/json den nil-slice som subnets då höll till JSON "null", men Kea
// kräver att "subnet4" är en array (även tom) - Kea vägrade starta med
// "syntax error, unexpected null, expecting [", vilket tog ner hela
// DHCP-tjänsten trots att den korrekt inte skulle dela ut några leaser.
func TestGenerateKeaConfigNoDHCPZonesEmitsEmptyArray(t *testing.T) {
	a := &Adapter{leaseDBPath: "/tmp/leases.csv"}
	cfg := &config.Config{}

	data, err := a.GenerateKeaConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateKeaConfig misslyckades: %v", err)
	}
	if bytes.Contains(data, []byte("null")) {
		t.Fatalf("genererad config innehåller \"null\" (subnet4 måste vara en tom array): %s", data)
	}

	var parsed KeaConfig
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("kunde inte tolka genererad config: %v", err)
	}
	if parsed.Dhcp4.Subnet4 == nil {
		t.Fatalf("subnet4 tolkades som null/nil, förväntade en tom array")
	}
	if len(parsed.Dhcp4.Subnet4) != 0 {
		t.Fatalf("förväntade 0 subnet4-poster, fick %d", len(parsed.Dhcp4.Subnet4))
	}
}
