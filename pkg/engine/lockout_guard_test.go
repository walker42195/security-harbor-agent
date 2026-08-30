package engine

import (
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/network"
	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func networkPhysicalDevices() []string { return network.PhysicalDevices() }

// Regressionstest för utlåsningen 2026-08-30: en config vars kort inte finns
// på maskinen får inte appliceras vid boot, för då matchar SSH-/Management-
// policyerna inget och default drop kapar administratörens anslutning.
func TestMissingConfiguredDevices(t *testing.T) {
	cases := []struct {
		name        string
		ifaces      []config.Interface
		wantMissing bool
	}{
		{
			name:        "nil-config",
			ifaces:      nil,
			wantMissing: false,
		},
		{
			name: "alla kort saknas",
			ifaces: []config.Interface{
				{Device: "kort-som-inte-finns-0", Enabled: true},
				{Device: "kort-som-inte-finns-1", Enabled: true},
			},
			wantMissing: true,
		},
		{
			name: "avstängda kort räknas inte",
			ifaces: []config.Interface{
				{Device: "kort-som-inte-finns-0", Enabled: false},
			},
			wantMissing: false,
		},
		{
			name: "VLAN räknas inte - de skapas av agenten själv",
			ifaces: []config.Interface{
				{Device: "kort-som-inte-finns-0", Enabled: true, VLANID: 10},
			},
			wantMissing: false,
		},
		{
			name: "loopback finns alltid: minst ett kort matchar => applicera",
			ifaces: []config.Interface{
				{Device: "kort-som-inte-finns-0", Enabled: true},
				{Device: firstPhysicalDeviceForTest(t), Enabled: true},
			},
			wantMissing: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := missingConfiguredDevices(&config.Config{Interfaces: tc.ifaces})
			if (got != nil) != tc.wantMissing {
				t.Fatalf("missingConfiguredDevices(%+v) = %v, ville saknade=%v",
					tc.ifaces, got, tc.wantMissing)
			}
		})
	}
}

// firstPhysicalDeviceForTest ger ett kortnamn som FAKTISKT finns på maskinen
// testet kör på. Hoppar över testfallet på en maskin helt utan fysiska kort
// (t.ex. en minimal container) i stället för att låtsas att det passerade.
func firstPhysicalDeviceForTest(t *testing.T) string {
	t.Helper()
	devs := networkPhysicalDevices()
	if len(devs) == 0 {
		t.Skip("inga fysiska nätverkskort på testmaskinen")
	}
	return devs[0]
}
