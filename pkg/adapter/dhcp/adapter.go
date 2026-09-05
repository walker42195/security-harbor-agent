package dhcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

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

// controlSocketPath ligger i samma katalog som lease-memfilen (som redan finns
// och är skrivbar för Kea), så ingen extra katalog behöver skapas.
func (a *Adapter) controlSocketPath() string {
	return filepath.Join(filepath.Dir(a.leaseDBPath), "kea4-ctrl-socket")
}

// DeleteLease frigör EN aktiv DHCP-lease via Kea:s kommandokanal (lease4-del),
// utan omstart. ip måste vara en giltig IPv4-adress. Returnerar nil om leasen
// togs bort ELLER inte fanns (idempotent), och fel vid socket-/protokollfel.
func (a *Adapter) DeleteLease(ctx context.Context, ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("ogiltig IP-adress %q", ip)
	}
	sock := a.controlSocketPath()
	cmd, _ := json.Marshal(map[string]interface{}{
		"command":   "lease4-del",
		"arguments": map[string]string{"ip-address": ip},
	})

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return fmt.Errorf("kunde inte nå Kea:s kommandosocket (%s) — kör en Apply så control-socket aktiveras: %w", sock, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}

	if _, err := conn.Write(cmd); err != nil {
		return fmt.Errorf("skrivning till Kea-socket misslyckades: %w", err)
	}
	// Signalera slut på kommando så Kea svarar och stänger.
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	respBytes, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("läsning från Kea-socket misslyckades: %w", err)
	}
	var resp []struct {
		Result int    `json:"result"`
		Text   string `json:"text"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil || len(resp) == 0 {
		return fmt.Errorf("oväntat svar från Kea: %s", string(respBytes))
	}
	// result: 0 = ok, 3 = tom (leasen fanns inte) — båda är OK/idempotent.
	switch resp[0].Result {
	case 0, 3:
		log.Printf("[dhcp] lease4-del %s → result=%d (%s)", ip, resp[0].Result, resp[0].Text)
		return nil
	default:
		return fmt.Errorf("Kea nekade lease4-del för %s: %s", ip, resp[0].Text)
	}
}

type KeaConfig struct {
	Dhcp4 Dhcp4Config `json:"Dhcp4"`
}

type Dhcp4Config struct {
	InterfacesConfig InterfacesConfig `json:"interfaces-config"`
	ControlSocket    *ControlSocket   `json:"control-socket,omitempty"`
	LeaseDatabase    LeaseDatabase    `json:"lease-database"`
	Subnet4          []Subnet4        `json:"subnet4"`
}

// ControlSocket aktiverar Kea:s kommandokanal (unix-socket) så agenten kan
// skicka t.ex. lease4-del för att frigöra en enskild lease utan omstart.
type ControlSocket struct {
	SocketType string `json:"socket-type"`
	SocketName string `json:"socket-name"`
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
			ControlSocket: &ControlSocket{
				SocketType: "unix",
				SocketName: a.controlSocketPath(),
			},
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
//
// forceRestart tvingar en omstart även när konfigurationen är oförändrad.
// Används vid UPPSTART, där agenten konfigurerar gränssnitten EFTER att Kea
// redan startat: Kea öppnar råa AF_PACKET-socketar mot varje gränssnitt vid
// start, och ett gränssnitt som ännu inte var uppe ger
// "DHCPSRV_OPEN_SOCKET_FAIL failed to open socket: the interface X is down".
// Kea upptäcker aldrig att kortet kommer upp senare och fortsätter med
// trasiga socketar — den tar emot förfrågningar men får aldrig ut sina svar,
// så klienterna DISCOVER:ar om och om igen, leases går ut och alla värdnamn
// försvinner. Uppmätt skarpt 2026-08-27: fyra av fem gränssnitt nere vid
// Keas start, 952 LEASE_OFFER mot 1 LEASE_ALLOC.
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, dryRun bool, forceRestart bool) error {
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
	restarted, err := svc.RestartIfNeeded(ctx, "kea-dhcp4-server.service", changed || forceRestart)
	if err != nil {
		return err
	}
	if !restarted {
		log.Printf("[DHCP] konfigurationen oförändrad - hoppar över omstart av kea-dhcp4-server.service")
	}
	return nil
}
