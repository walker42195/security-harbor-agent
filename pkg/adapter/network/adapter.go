package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

type DiscoveredInterface struct {
	Name         string   `json:"name"`
	MAC          string   `json:"mac"`
	IPs          []string `json:"ips"`
	IsUP         bool     `json:"is_up"`
	IsLoopback   bool     `json:"is_loopback"`
	IsVLAN       bool     `json:"is_vlan"`
	ParentDevice string   `json:"parent_device,omitempty"`
}

type Adapter struct{}

func NewAdapter() *Adapter {
	return &Adapter{}
}

// DiscoverInterfaces upptäcker alla fysiska och virtuella nätverkskort på Linux-värden.
func (a *Adapter) DiscoverInterfaces() ([]DiscoveredInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("misslyckades hämta nätverkskort: %w", err)
	}

	var result []DiscoveredInterface
	for _, iface := range ifaces {
		isLoopback := (iface.Flags & net.FlagLoopback) != 0
		isUP := (iface.Flags & net.FlagUp) != 0

		addrs, _ := iface.Addrs()
		var ips []string
		for _, addr := range addrs {
			ips = append(ips, addr.String())
		}

		isVLAN := strings.Contains(iface.Name, ".")
		parent := ""
		if isVLAN {
			parts := strings.Split(iface.Name, ".")
			parent = parts[0]
		}

		result = append(result, DiscoveredInterface{
			Name:         iface.Name,
			MAC:          iface.HardwareAddr.String(),
			IPs:          ips,
			IsUP:         isUP,
			IsLoopback:   isLoopback,
			IsVLAN:       isVLAN,
			ParentDevice: parent,
		})
	}

	return result, nil
}

// ApplyInterfaceConfig tillämpar IP-adresser, länkstatus och VLAN-gränssnitt på Linux.
func (a *Adapter) ApplyInterfaceConfig(ctx context.Context, iface config.Interface) error {
	if iface.Device == "" {
		return fmt.Errorf("interface device saknas")
	}

	// 1. Om detta är ett VLAN-interface, skapa Linux-vlan-gränssnittet om det inte redan finns
	if iface.VLANID > 0 && iface.Parent != "" {
		vlanDev := fmt.Sprintf("%s.%d", iface.Parent, iface.VLANID)
		if iface.Device != vlanDev {
			iface.Device = vlanDev
		}

		// Kontrollera om VLAN-interfacet finns
		_, err := net.InterfaceByName(iface.Device)
		if err != nil {
			// Skapa VLAN via ip link
			cmd := exec.CommandContext(ctx, "ip", "link", "add", "link", iface.Parent, "name", iface.Device, "type", "vlan", "id", strconv.Itoa(iface.VLANID))
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("misslyckades skapa VLAN %s on %s: %w - %s", iface.Device, iface.Parent, err, string(out))
			}
		}
	}

	// 2. Sätt interface UP eller DOWN
	state := "up"
	if !iface.Enabled {
		state = "down"
	}
	cmdState := exec.CommandContext(ctx, "ip", "link", "set", iface.Device, state)
	_ = cmdState.Run()

	// 3. Om statisk IPv4 är angiven, tilldela IP-adressen
	if iface.Enabled && iface.AddressType == "static" && iface.IPv4 != "" {
		// Flush gamla adresser först för att undvika konflikter
		_ = exec.CommandContext(ctx, "ip", "addr", "flush", "dev", iface.Device).Run()

		cmdAddr := exec.CommandContext(ctx, "ip", "addr", "add", iface.IPv4, "dev", iface.Device)
		out, err := cmdAddr.CombinedOutput()
		if err != nil && !strings.Contains(string(out), "File exists") {
			return fmt.Errorf("misslyckades sätta IP %s på %s: %w - %s", iface.IPv4, iface.Device, err, string(out))
		}
	}

	return nil
}

// ApplyDNSConfig uppdaterar systemets DNS-resolvrar i /etc/resolv.conf baserat på inskrivna DNS-servrar.
func (a *Adapter) ApplyDNSConfig(ctx context.Context, interfaces []config.Interface) error {
	var dnsList []string
	for _, iface := range interfaces {
		if iface.Enabled && len(iface.DNSServers) > 0 {
			dnsList = append(dnsList, iface.DNSServers...)
		}
	}

	if len(dnsList) == 0 {
		return nil
	}

	var sb strings.Builder
	sb.WriteString("# Genererad av Security Harbor Agent\n")
	for _, dns := range dnsList {
		trimmed := strings.TrimSpace(dns)
		if trimmed != "" {
			sb.WriteString(fmt.Sprintf("nameserver %s\n", trimmed))
		}
	}

	return os.WriteFile("/etc/resolv.conf", []byte(sb.String()), 0644)
}
