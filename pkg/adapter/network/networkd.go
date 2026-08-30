package network

// systemd-networkd-backend (rå .network/.netdev-filer).
//
// Används när networkd äger nätverket men netplan inte finns — t.ex. en
// Debian-installation som satts upp med networkd i stället för ifupdown.
// Filerna läggs i /etc/systemd/network/ med prefixet 05-, vilket är det som
// gör dem verksamma: networkd väljer den FÖRSTA matchande filen i
// bokstavsordning över /etc, /run och /usr, så 05- vinner både över
// netplans renderade 10-netplan-*.network och över installationens
// catch-all zzzz-dracut-default.network (som annars DHCP:ar varje kort som
// ingen annan deklarerat — se paketkommentaren i netplan.go).
//
// VLAN kräver två filer: en .netdev som SKAPAR kortet och en .network som
// adresserar det, plus en VLAN=-rad i förälderns .network så att networkd
// vet att den ska hänga på subinterfacet.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

type networkdBackend struct{}

func (b *networkdBackend) Name() string { return "systemd-networkd" }

const (
	networkdDir    = "/etc/systemd/network"
	networkdPrefix = "05-security-harbor-"
)

// Write renderar en fil per gränssnitt och städar bort filer som hör till
// gränssnitt som inte längre finns i konfigurationen. Städningen är viktig:
// en kvarlämnad .network för ett borttaget kort fortsätter annars gälla vid
// varje boot, osynligt för administratören som tog bort kortet i GUI:t.
func (b *networkdBackend) Write(ctx context.Context, ifaces []config.Interface) (bool, error) {
	files, err := renderNetworkdFiles(ifaces)
	if err != nil {
		return false, err
	}

	if err := os.MkdirAll(networkdDir, 0o755); err != nil {
		return false, fmt.Errorf("kunde inte skapa %s: %w", networkdDir, err)
	}

	changed := false
	for name, content := range files {
		path := filepath.Join(networkdDir, name)
		if previous, ok := readFileIfExists(path); ok && previous == content {
			continue
		}
		if err := writeFileAtomic(path, content); err != nil {
			return changed, fmt.Errorf("kunde inte skriva %s: %w", path, err)
		}
		changed = true
	}

	stale, err := filepath.Glob(filepath.Join(networkdDir, networkdPrefix+"*"))
	if err != nil {
		return changed, nil // glob-mönstret är konstant; ett fel här går inte att åtgärda
	}
	for _, path := range stale {
		if _, wanted := files[filepath.Base(path)]; wanted {
			continue
		}
		if err := os.Remove(path); err == nil {
			changed = true
		}
	}
	return changed, nil
}

// renderNetworkdFiles bygger hela filuppsättningen i minnet innan något
// skrivs, så att ett renderingsfel inte lämnar halva konfigurationen på disk.
func renderNetworkdFiles(ifaces []config.Interface) (map[string]string, error) {
	files := map[string]string{}
	// VLAN som ska hängas på respektive förälder, för VLAN=-raderna nedan.
	vlansByParent := map[string][]string{}

	for _, iface := range ifaces {
		device := deviceNameFor(iface)
		if device == "" {
			continue
		}
		if !safeDeviceName.MatchString(device) {
			return nil, fmt.Errorf("gränssnitt %q har ett ogiltigt enhetsnamn", device)
		}
		isVLAN := iface.VLANID > 0 && iface.Parent != ""
		if isVLAN && !iface.Enabled {
			continue // avstängd VLAN skapas inte alls
		}
		if isVLAN {
			if !safeDeviceName.MatchString(iface.Parent) {
				return nil, fmt.Errorf("VLAN %q har ett ogiltigt föräldrakort %q", device, iface.Parent)
			}
			vlansByParent[iface.Parent] = append(vlansByParent[iface.Parent], device)
			files[networkdPrefix+device+".netdev"] = fmt.Sprintf(
				"# Skriven av Security Harbor-agenten - redigera inte för hand.\n"+
					"[NetDev]\nName=%s\nKind=vlan\n\n[VLAN]\nId=%d\n", device, iface.VLANID)
		}

		body, err := renderNetworkdNetwork(iface, device, ifaces)
		if err != nil {
			return nil, err
		}
		files[networkdPrefix+device+".network"] = body
	}

	// Hängl VLAN på föräldrarnas .network-filer. Görs i efterhand eftersom
	// föräldern kan ha renderats innan vi visste vilka VLAN som hör till den.
	for parent, vlans := range vlansByParent {
		name := networkdPrefix + parent + ".network"
		body, ok := files[name]
		if !ok {
			continue // föräldern ägs inte av oss
		}
		sort.Strings(vlans)
		var b strings.Builder
		for _, v := range vlans {
			fmt.Fprintf(&b, "VLAN=%s\n", v)
		}
		files[name] = insertIntoNetworkSection(body, b.String())
	}
	return files, nil
}

// insertIntoNetworkSection lägger till rader sist i [Network]-sektionen.
// Sektionen är alltid den sista i filerna vi själva renderar, så det räcker
// att lägga raderna på slutet.
func insertIntoNetworkSection(body, extra string) string {
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return body + extra
}

func renderNetworkdNetwork(iface config.Interface, device string, all []config.Interface) (string, error) {
	isWAN := strings.EqualFold(iface.Zone, "WAN")

	var b strings.Builder
	b.WriteString("# Skriven av Security Harbor-agenten - redigera inte för hand.\n")
	fmt.Fprintf(&b, "[Match]\nName=%s\n\n", device)

	if iface.MTU > 0 || strings.TrimSpace(iface.MACAddress) != "" || !iface.Enabled {
		b.WriteString("[Link]\n")
		if !iface.Enabled {
			// Motsvarar netplans activation-mode: off — kortet finns kvar men
			// tas aldrig upp.
			b.WriteString("ActivationPolicy=down\n")
		}
		if iface.MTU > 0 {
			fmt.Fprintf(&b, "MTUBytes=%d\n", iface.MTU)
		}
		if mac := strings.TrimSpace(iface.MACAddress); mac != "" {
			if !safeMAC.MatchString(mac) {
				return "", fmt.Errorf("gränssnitt %q har en ogiltig MAC-adress %q", device, mac)
			}
			fmt.Fprintf(&b, "MACAddress=%s\n", mac)
		}
		b.WriteString("\n")
	}

	b.WriteString("[Network]\n")
	// IPv6 av, av samma skäl som i de andra backendarna.
	b.WriteString("LinkLocalAddressing=no\nIPv6AcceptRA=no\n")

	if iface.AddressType == "static" && iface.IPv4 != "" {
		if !safeIPv4CIDR.MatchString(iface.IPv4) {
			return "", fmt.Errorf("gränssnitt %q har en ogiltig IPv4-adress %q (ska vara t.ex. 10.0.0.9/24)", device, iface.IPv4)
		}
		b.WriteString("DHCP=no\n")
		fmt.Fprintf(&b, "Address=%s\n", iface.IPv4)
		if isWAN {
			if gw := strings.TrimSpace(iface.Gateway); gw != "" {
				if !safeIP.MatchString(gw) {
					return "", fmt.Errorf("gränssnitt %q har en ogiltig gateway %q", device, gw)
				}
				fmt.Fprintf(&b, "Gateway=%s\n", gw)
			}
			for _, ns := range sanitizedDNS(iface) {
				fmt.Fprintf(&b, "DNS=%s\n", ns)
			}
		}
		return b.String(), nil
	}

	b.WriteString("DHCP=ipv4\n")
	if !CarriesDefaultRoute(iface, all) {
		// Motsvarigheten till netplans dhcp4-overrides: hämta adressen, men
		// aldrig default-rutt eller DNS (se paketkommentaren i netplan.go).
		// Gäller INTERNA kort — i host-läge finns inget WAN och kortet är
		// maskinens uppkoppling, se CarriesDefaultRoute.
		b.WriteString("\n[DHCPv4]\nUseRoutes=no\nUseGateway=no\nUseDNS=no\n")
	}
	return b.String(), nil
}

// Reconfigure laddar om de skrivna filerna och tillämpar dem på ETT kort.
func (b *networkdBackend) Reconfigure(ctx context.Context, device string) error {
	return reloadAndReconfigure(ctx, device)
}
