package dhcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

type Adapter struct {
	configPath  string
	leaseDBPath string
}

const defaultLeaseDBPath = "/var/lib/kea/kea-leases4.csv"

func NewAdapter(configPath string) *Adapter {
	if configPath == "" {
		configPath = "/etc/kea/kea-dhcp4.conf"
	}
	return &Adapter{configPath: configPath, leaseDBPath: defaultLeaseDBPath}
}

// LeaseDatabasePath returnerar sökvägen till Kea:s lease-memfile, som
// pkg/adapter/dns läser (via ParseLeaseFile) för att registrera
// DHCP-tilldelade värdnamn i den lokala DNS-zonen.
func (a *Adapter) LeaseDatabasePath() string {
	return a.leaseDBPath
}

type KeaConfig struct {
	Dhcp4 Dhcp4Config `json:"Dhcp4"`
}

type Dhcp4Config struct {
	InterfacesConfig InterfacesConfig `json:"interfaces-config"`
	LeaseDatabase    LeaseDatabase    `json:"lease-database"`
	Subnet4          []Subnet4        `json:"subnet4"`
}

type InterfacesConfig struct {
	Interfaces []string `json:"interfaces"`
}

type LeaseDatabase struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Persist bool   `json:"persist"`
}

type Subnet4 struct {
	Subnet       string        `json:"subnet"`
	Pools        []Pool        `json:"pools"`
	OptionData   []OptionData  `json:"option-data"`
	Reservations []Reservation `json:"reservations,omitempty"`
}

type Pool struct {
	Pool string `json:"pool"`
}

type OptionData struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type Reservation struct {
	HwAddress string `json:"hw-address"`
	IPAddress string `json:"ip-address"`
	Hostname  string `json:"hostname,omitempty"`
}

// GenerateKeaConfig omvandlar alla aktiva DHCP-scopes från `cfg.Interfaces` till Kea-format.
func (a *Adapter) GenerateKeaConfig(cfg *config.Config) ([]byte, error) {
	var listeningIfaces []string
	var subnets []Subnet4

	for _, iface := range cfg.Interfaces {
		if !iface.Enabled || iface.Zone == "WAN" || iface.DHCP == nil || !iface.DHCP.Enabled {
			continue
		}

		listeningIfaces = append(listeningIfaces, iface.Device)

		// Hitta nätverksadress från IPv4 (t.ex. 192.168.10.1/24)

		subnet4 := Subnet4{
			Subnet: iface.IPv4,
			Pools: []Pool{
				{Pool: fmt.Sprintf("%s - %s", iface.DHCP.RangeStart, iface.DHCP.RangeEnd)},
			},
			OptionData: []OptionData{
				{Name: "routers", Data: iface.DHCP.Gateway},
			},
		}

		if len(iface.DHCP.DNSServers) > 0 {
			subnet4.OptionData = append(subnet4.OptionData, OptionData{
				Name: "domain-name-servers",
				Data: iface.DHCP.DNSServers[0],
			})
		}

		for _, res := range iface.DHCP.Reservations {
			subnet4.Reservations = append(subnet4.Reservations, Reservation{
				HwAddress: res.MAC,
				IPAddress: res.IP,
				Hostname:  res.Hostname,
			})
		}

		subnets = append(subnets, subnet4)
	}

	if len(listeningIfaces) == 0 {
		listeningIfaces = []string{"*"}
	}

	keaCfg := KeaConfig{
		Dhcp4: Dhcp4Config{
			InterfacesConfig: InterfacesConfig{Interfaces: listeningIfaces},
			LeaseDatabase: LeaseDatabase{
				Type:    "memfile",
				Name:    a.leaseDBPath,
				Persist: true,
			},
			Subnet4: subnets,
		},
	}

	return json.MarshalIndent(keaCfg, "", "  ")
}

// ApplyConfig skriver kea-dhcp4.conf och startar om Kea DHCP-servern om DHCP-scopes finns.
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, dryRun bool) error {
	data, err := a.GenerateKeaConfig(cfg)
	if err != nil {
		return fmt.Errorf("misslyckades generera Kea konfiguration: %w", err)
	}

	if dryRun {
		return nil
	}

	_ = os.MkdirAll(filepath.Dir(a.configPath), 0755)
	if err := os.WriteFile(a.configPath, data, 0644); err != nil {
		return fmt.Errorf("misslyckades skriva %s: %w", a.configPath, err)
	}

	// Starta om kea-dhcp4-server om tjänsten finns
	_ = exec.CommandContext(ctx, "systemctl", "restart", "kea-dhcp4-server.service").Run()
	return nil
}
