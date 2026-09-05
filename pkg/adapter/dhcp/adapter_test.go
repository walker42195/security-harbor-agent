package dhcp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
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

func TestKeaConfigHasControlSocket(t *testing.T) {
	a := NewAdapter("")
	cfg := &config.Config{Interfaces: []config.Interface{
		{Device: "ens18.5", Zone: "LAN", Enabled: true, IPv4: "10.5.5.1/24",
			DHCP: &config.DHCPConfig{Enabled: true, RangeStart: "10.5.5.100", RangeEnd: "10.5.5.200", Gateway: "10.5.5.1"}},
	}}
	data, err := a.GenerateKeaConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateKeaConfig: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, `"control-socket"`) || !strings.Contains(s, `"socket-type": "unix"`) || !strings.Contains(s, "kea4-ctrl-socket") {
		t.Errorf("control-socket saknas i genererad Kea-config:\n%s", s)
	}

	// Kea 3.x KRÄVER att socket-name ligger under /run/kea — annars vägrar
	// hela DHCP-servern starta. Detta test hade fångat regressionen i 0.47.0.
	if !strings.Contains(s, `"socket-name": "/run/kea/kea4-ctrl-socket"`) {
		t.Errorf("control-socket måste ligga under /run/kea (Kea 3.x-krav):\n%s", s)
	}
}

func TestDeleteLeaseValidatesIP(t *testing.T) {
	a := NewAdapter("")
	if err := a.DeleteLease(context.Background(), "inte-en-ip"); err == nil {
		t.Error("förväntade fel för ogiltig IP")
	}
}

// TestGenerateKeaConfigValidatesWithKea kör `kea-dhcp4 -t` på den genererade
// configen när Kea finns i PATH — fångar allt en viss Kea-version underkänner
// (t.ex. control-socket-sökvägen). Skippas där Kea saknas (t.ex. CI utan Kea).
func TestGenerateKeaConfigValidatesWithKea(t *testing.T) {
	kea, err := exec.LookPath("kea-dhcp4")
	if err != nil {
		t.Skip("kea-dhcp4 saknas i PATH — hoppar skarp config-validering")
	}
	a := NewAdapter("")
	cfg := &config.Config{Interfaces: []config.Interface{
		{Device: "ens18.5", Zone: "LAN", Enabled: true, IPv4: "10.5.5.1/24",
			DHCP: &config.DHCPConfig{Enabled: true, RangeStart: "10.5.5.100", RangeEnd: "10.5.5.200", Gateway: "10.5.5.1", DNSServers: []string{"10.5.5.1"}}},
	}}
	data, err := a.GenerateKeaConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateKeaConfig: %v", err)
	}
	tmp, err := os.CreateTemp("", "kea-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	out, err := exec.Command(kea, "-t", tmp.Name()).CombinedOutput()
	if err != nil {
		t.Fatalf("kea-dhcp4 -t underkände genererad config: %v\n%s", err, out)
	}
}
