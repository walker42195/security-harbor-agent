package dhcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/svc"
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
	ID           int           `json:"id"`
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
	// Initieras som tom slice (inte nil): en nil-slice marshalas till JSON
	// "null" av encoding/json, men Kea kräver att subnet4 är en array (även
	// tom) - annars vägrar Kea starta med "syntax error, unexpected null,
	// expecting [" så fort DHCP är helt avaktiverat (0 aktiva scopes).
	subnets := []Subnet4{}

	for _, iface := range cfg.Interfaces {
		if !iface.Enabled || iface.Zone == "WAN" || iface.DHCP == nil || !iface.DHCP.Enabled {
			continue
		}

		listeningIfaces = append(listeningIfaces, iface.Device)

		// Hitta nätverksadress från IPv4 (t.ex. 192.168.10.1/24)

		// Kea kräver ett unikt "id" per subnet4-post (upptäckt live
		// 2026-08-24: "DHCP4_PARSER_FAIL ... subnet configuration failed:
		// missing parameter 'id'" — fältet saknades helt i den genererade
		// configen, vilket fick Kea att vägra starta så fort mer än en
		// DHCP-aktiverad zon fanns/reservations-uppslag först var påslaget).
		// Index+1 räcker: Kea kräver bara att det är unikt INOM den
		// aktuella configen, inte att det är stabilt mellan omgenereringar.
		subnet4 := Subnet4{
			ID:     len(subnets) + 1,
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

	// Skrivningen är atomär och sker via en temp-fil i SAMMA katalog: det
	// kräver bara skrivrätt på KATALOGEN (som install.sh ger tjänstekontot via
	// grupp-skriv på /etc/kea), INTE på själva målfilen — kea-dhcp4.conf
	// installeras av paketet som root:root, och en direkt os.WriteFile på den
	// gav "permission denied" (upptäckt på ny server 2026-08-23 när LAN
	// ändrades från DHCP till statisk). Se svc.WriteIfChanged.
	_ = os.MkdirAll(filepath.Dir(a.configPath), 0755)
	changed, err := svc.WriteIfChanged(a.configPath, data)
	if err != nil {
		return fmt.Errorf("misslyckades skriva %s: %w", a.configPath, err)
	}

	// Kea startas om bara när konfigurationen ändrats (eller om den inte redan
	// kör). En omstart tar DHCP ur drift, och konfigurationen är typiskt
	// identisk vid t.ex. en agentuppdatering.
	restarted, err := svc.RestartIfNeeded(ctx, "kea-dhcp4-server.service", changed)
	if err != nil {
		return err
	}
	if !restarted {
		log.Printf("[DHCP] konfigurationen oförändrad - hoppar över omstart av kea-dhcp4-server.service")
	}
	return nil
}
