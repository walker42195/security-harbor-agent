package network

// Persistent gränssnittskonfiguration via netplan.
//
// Bakgrunden (skarp incident 2026-08-26, brandväggen på 10.0.0.9): agenten
// satte statiska adresser enbart imperativt med `ip addr add`. Det höll bara
// tills något annat rörde kortet. På Ubuntu 26.04 äger systemd-networkd
// nätverket, och en catch-all-fil från installationen
// (/run/systemd/network/zzzz-dracut-default.network, `Kind=!* → DHCP=yes`)
// DHCP:ar varje kort som inte deklarerats i netplan. LAN-kortet ens19 var
// aldrig deklarerat, så vid varje omstart av agenten — t.ex. den
// automatiska självuppdateringen 22:55 — tappade brandväggen sin statiska
// management-IP 10.0.0.9 och hamnade på en DHCP-adress från LAN:s egen
// DHCP-server, komplett med en andra default-rutt. Ingen loggrad, eftersom
// ingenting hade FELAT: agenten hade helt enkelt aldrig skrivit ner adressen
// någonstans som överlevde en omstart.
//
// Sätter administratören en adress i GUI:t ska den därför gälla på OS-nivå,
// precis som om den satts med nmcli/nmtui — inte bara i agentens minne. Den
// här filen skriver därför en riktig netplan-konfiguration som blir systemets
// sanning. Netplan är rätt lager på den här plattformen: det är Ubuntus
// kanoniska nätverkskonfiguration (NetworkManager och nmcli finns inte
// installerade), det är redan där installationen lägger WAN-kortet, och den
// renderade filen (/run/systemd/network/10-netplan-*.network) sorterar före
// zzzz-dracut-default.network — så fallbacken slutar gälla för de kort vi
// deklarerar.
//
// Filen vi äger är helt vår: den skrivs om i sin helhet vid varje applicering
// och innehåller ALLA gränssnitt agenten känner till. Installationens egen
// 00-installer-config.yaml lämnas orörd — netplan slår ihop filerna och vår
// högre prefix (90-) vinner för de nycklar vi sätter.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// NetplanPath är den enda netplan-fil agenten äger och skriver om.
// 90- gör att den sorterar EFTER installationens 00-installer-config.yaml,
// så våra nycklar vinner när netplan slår ihop filerna.
const NetplanPath = "/etc/netplan/90-security-harbor.yaml"

// safeDeviceName begränsar vad som får skrivas som en YAML-nyckel eller ett
// värde i netplan-filen. Enhetsnamn kommer från konfigurationen (som i sin
// tur kan komma från GUI:t), och renderingen nedan är strängbaserad — utan
// den här kontrollen hade ett namn med kolon eller radbrytning kunnat bryta
// sig ut och injicera godtycklig netplan-YAML. Linux-enhetsnamn är ändå
// begränsade till det här teckenurvalet (IFNAMSIZ, inga blanksteg).
var safeDeviceName = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,15}$`)

// safeIPv4CIDR / safeIP validerar adresser innan de skrivs. Adresserna
// valideras redan av validateInterfaces vid Apply, men renderingen får inte
// LITA på det: netplan-filen skrivs även vid boot från en running.json som
// kan ha skrivits av en äldre agent utan den valideringen.
var (
	safeIPv4CIDR = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$`)
	safeIP       = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	safeMAC      = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`)
)

// RenderNetplan bygger hela netplan-dokumentet för de gränssnitt agenten
// äger. Gränssnitt hanteras olika beroende på typ:
//
//   - Fysiska kort hamnar under "ethernets", VLAN under "vlans" (med id +
//     link), vilket gör att VLAN-subinterfacen numera återskapas av netplan
//     vid boot i stället för att bero på att agenten hinner köra `ip link
//     add` (som tidigare — och som betydde att en VLAN inte fanns alls under
//     de sekunder innan agenten startat).
//   - ENDAST WAN får default-rutt och DNS. Ett internt kort som hämtar
//     routers/DNS via DHCP ger brandväggen konkurrerande default-rutter och
//     ett slumpartat egress-val — trafik kan lämna fel kort, förbi
//     masquerade och LAN→WAN-policyn, och fastnar på Default Deny. Därför
//     sätts dhcp4-overrides (use-routes/use-dns: false) på interna kort, och
//     "routes:" skrivs aldrig för dem.
//   - Avstängda gränssnitt: fysiska kort deklareras med activation-mode: off
//     (kortet finns men tas inte upp), VLAN utelämnas helt — då skapar
//     netplan dem inte vid boot, vilket är precis vad "avstängd" betyder för
//     ett virtuellt kort.
func RenderNetplan(ifaces []config.Interface) (string, error) {
	ethernets := map[string]string{}
	vlans := map[string]string{}

	for _, iface := range ifaces {
		device := iface.Device
		if iface.VLANID > 0 && iface.Parent != "" {
			// Samma normalisering som ApplyInterfaceConfig gör: enhetsnamnet
			// härleds ur förälder + vlan-id, inte ur Device-fältet.
			device = fmt.Sprintf("%s.%d", iface.Parent, iface.VLANID)
		}
		if device == "" {
			continue
		}
		if !safeDeviceName.MatchString(device) {
			return "", fmt.Errorf("gränssnitt %q har ett ogiltigt enhetsnamn för netplan", device)
		}

		isVLAN := iface.VLANID > 0 && iface.Parent != ""
		if isVLAN && !iface.Enabled {
			continue // avstängd VLAN → skapa den inte alls
		}
		if isVLAN && !safeDeviceName.MatchString(iface.Parent) {
			return "", fmt.Errorf("VLAN %q har ett ogiltigt föräldrakort %q", device, iface.Parent)
		}

		body, err := renderInterfaceBody(iface, isVLAN, ifaces)
		if err != nil {
			return "", err
		}
		if isVLAN {
			vlans[device] = body
		} else {
			ethernets[device] = body
		}
	}

	var b strings.Builder
	b.WriteString("# Skriven av Security Harbor-agenten - redigera inte för hand.\n")
	b.WriteString("# Ändringar görs i GUI:t och skrivs om hit vid varje applicering.\n")
	b.WriteString("network:\n")
	b.WriteString("  version: 2\n")
	b.WriteString("  renderer: networkd\n")
	writeSection(&b, "ethernets", ethernets)
	writeSection(&b, "vlans", vlans)
	return b.String(), nil
}

// writeSection skriver en netplan-sektion med nycklarna i bokstavsordning, så
// att identisk konfiguration alltid ger en byte-identisk fil. Det är vad som
// gör "har filen ändrats?"-jämförelsen i WritePersistentConfig meningsfull —
// utan stabil ordning hade varje applicering sett ut som en ändring och
// triggat en onödig omkonfigurering av kortet.
func writeSection(b *strings.Builder, name string, entries map[string]string) {
	if len(entries) == 0 {
		return
	}
	devices := make([]string, 0, len(entries))
	for d := range entries {
		devices = append(devices, d)
	}
	sort.Strings(devices)

	fmt.Fprintf(b, "  %s:\n", name)
	for _, d := range devices {
		fmt.Fprintf(b, "    %s:\n", d)
		b.WriteString(entries[d])
	}
}

func renderInterfaceBody(iface config.Interface, isVLAN bool, all []config.Interface) (string, error) {
	var b strings.Builder
	isWAN := strings.EqualFold(iface.Zone, "WAN")
	// uplink skiljer sig från isWAN bara i host-läge, där det inte finns
	// någon WAN-zon och maskinens enda kort ändå måste bära default-rutt och
	// ta DNS från DHCP. Se CarriesDefaultRoute.
	uplink := CarriesDefaultRoute(iface, all)

	if isVLAN {
		fmt.Fprintf(&b, "      id: %d\n", iface.VLANID)
		fmt.Fprintf(&b, "      link: %s\n", iface.Parent)
	}
	if !iface.Enabled {
		// Gäller bara fysiska kort; avstängda VLAN utelämnas av anroparen.
		b.WriteString("      activation-mode: off\n")
	}
	if iface.MTU > 0 {
		fmt.Fprintf(&b, "      mtu: %d\n", iface.MTU)
	}
	if mac := strings.TrimSpace(iface.MACAddress); mac != "" {
		if !safeMAC.MatchString(mac) {
			return "", fmt.Errorf("gränssnitt %q har en ogiltig MAC-adress %q", iface.Device, mac)
		}
		fmt.Fprintf(&b, "      macaddress: %s\n", mac)
	}

	// IPv6 lämnas medvetet avstängt: konfigurationsmodellen har inga
	// IPv6-fält, och en oväntad RA-inlärd default-rutt via ett internt kort
	// skulle ge samma egress-problem som en DHCP-inlärd (se paketkommentaren).
	b.WriteString("      dhcp6: false\n")
	if !uplink {
		b.WriteString("      accept-ra: false\n")
	}

	switch {
	case iface.AddressType == "static" && iface.IPv4 != "":
		if !safeIPv4CIDR.MatchString(iface.IPv4) {
			return "", fmt.Errorf("gränssnitt %q har en ogiltig IPv4-adress %q (ska vara t.ex. 10.0.0.9/24)", iface.Device, iface.IPv4)
		}
		b.WriteString("      dhcp4: false\n")
		fmt.Fprintf(&b, "      addresses: [%s]\n", iface.IPv4)
		if isWAN {
			if gw := strings.TrimSpace(iface.Gateway); gw != "" {
				if !safeIP.MatchString(gw) {
					return "", fmt.Errorf("gränssnitt %q har en ogiltig gateway %q", iface.Device, gw)
				}
				b.WriteString("      routes:\n")
				b.WriteString("        - to: default\n")
				fmt.Fprintf(&b, "          via: %s\n", gw)
			}
			if ns, err := renderNameservers(iface); err != nil {
				return "", err
			} else {
				b.WriteString(ns)
			}
		}

	default:
		// DHCP (eller statiskt utan adress, vilket inte går att applicera —
		// då är DHCP det enda vettiga: kortet får åtminstone en adress).
		b.WriteString("      dhcp4: true\n")
		if !uplink {
			b.WriteString("      dhcp4-overrides:\n")
			b.WriteString("        use-routes: false\n")
			b.WriteString("        use-dns: false\n")
		}
	}

	return b.String(), nil
}

// renderNameservers skriver DNS-servrar för WAN. För interna gränssnitt
// betyder DNSServers-fältet något helt annat — det är vad brandväggen delar
// UT till klienterna via DHCP (typiskt brandväggens egen adress) — och ska
// därför aldrig hamna i brandväggens egen resolver.
func renderNameservers(iface config.Interface) (string, error) {
	var addrs []string
	for _, ns := range iface.DNSServers {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			continue
		}
		if !safeIP.MatchString(ns) {
			return "", fmt.Errorf("gränssnitt %q har en ogiltig DNS-server %q", iface.Device, ns)
		}
		addrs = append(addrs, ns)
	}
	if len(addrs) == 0 {
		return "", nil
	}
	return fmt.Sprintf("      nameservers:\n        addresses: [%s]\n", strings.Join(addrs, ", ")), nil
}

// WritePersistentConfig skriver netplan-filen och låter netplan generera om
// systemd-networkd-konfigurationen. Returnerar true om filen faktiskt
// ändrades — anroparen använder det för att avgöra om något kort behöver
// konfigureras om.
//
// Filen skrivs atomärt (temp + rename) med läge 0600: netplan vägrar
// numera läsa filer som är läsbara för alla och skulle annars logga en
// varning vid varje generate.
//
// Misslyckas `netplan generate` läggs den GAMLA filen tillbaka. Annars hade
// en trasig fil legat kvar och slagit till vid nästa omstart — långt från
// den ändring som orsakade den, på en brandvägg som då startar utan
// nätverk.
func (b *netplanBackend) Write(ctx context.Context, ifaces []config.Interface) (bool, error) {
	rendered, err := RenderNetplan(ifaces)
	if err != nil {
		return false, err
	}

	previous, hadPrevious := readFileIfExists(NetplanPath)
	if hadPrevious && previous == rendered {
		return false, nil
	}

	if err := writeFileAtomic(NetplanPath, rendered); err != nil {
		return false, fmt.Errorf("kunde inte skriva %s: %w", NetplanPath, err)
	}

	if out, err := exec.CommandContext(ctx, "netplan", "generate").CombinedOutput(); err != nil {
		restorePrevious(previous, hadPrevious)
		return false, fmt.Errorf("netplan avvisade konfigurationen: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return true, nil
}

// ReconfigureDevice får systemd-networkd att tillämpa den nyss genererade
// konfigurationen på ETT kort. Medvetet inte `netplan apply`, som rör alla
// kort samtidigt: en ändring på ett gränssnitt ska aldrig bryta länken på de
// andra (samma princip som engine.applyInterfaces bygger på).
//
// `networkctl reload` läser in de genererade filerna; `reconfigure` tillämpar
// dem på kortet. Reload görs per anrop — den är billig och idempotent.
func (b *netplanBackend) Reconfigure(ctx context.Context, device string) error {
	return reloadAndReconfigure(ctx, device)
}

func readFileIfExists(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func writeFileAtomic(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".security-harbor-netplan-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op efter en lyckad rename

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// restorePrevious lägger tillbaka den tidigare netplan-filen efter ett
// avvisat generate. Fanns ingen fil sedan tidigare tas vår trasiga bort helt.
// Fel här kan inte hanteras meningsfullt — anroparen returnerar ändå
// generate-felet, som är det administratören behöver se — men de loggas via
// det felet i stället för att tystna.
func restorePrevious(previous string, hadPrevious bool) {
	if !hadPrevious {
		_ = os.Remove(NetplanPath)
		return
	}
	_ = writeFileAtomic(NetplanPath, previous)
	// Generera om från den återställda filen, så att det som ligger i
	// /run/systemd/network matchar det som ligger i /etc igen.
	_ = exec.Command("netplan", "generate").Run()
}

// AdoptSystemAddressing läser hur ett kort FAKTISKT är konfigurerat på
// OS-nivå och returnerar motsvarande konfigurationsvärden
// (address_type, ipv4-CIDR, gateway).
//
// Används vid en färsk installation: agenten ska ta över det som redan är
// inställt, inte påtvinga något. Är kortet satt på DHCP behålls DHCP; har
// det redan en statisk adress adopteras den adressen oförändrad. Det
// undviker båda fällorna — dels att en hårdkodad seed-IP flyttar lådan och
// kapar administratörens session vid första appliceringen, dels att en
// medvetet statiskt satt management-adress tyst byts mot en DHCP-lease.
//
// Kärnan markerar DHCP-tilldelade adresser med "dynamic" i `ip addr`; allt
// annat är permanent, dvs. statiskt satt. Det är samma signal som
// removeStaticAddresses redan bygger på.
func AdoptSystemAddressing(device string) (addressType, ipv4, gateway string) {
	if device == "" {
		return "dhcp", "", ""
	}
	out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", device).Output()
	if err != nil {
		return "dhcp", "", ""
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		var cidr string
		for i, f := range fields {
			if f == "inet" && i+1 < len(fields) {
				cidr = fields[i+1]
				break
			}
		}
		if cidr == "" || strings.HasPrefix(cidr, "127.") {
			continue
		}
		if strings.Contains(line, "dynamic") {
			// En aktiv DHCP-lease: kortet är inställt på DHCP.
			return "dhcp", "", ""
		}
		return "static", cidr, defaultGatewayFor(device)
	}

	// Ingen adress alls (kortet är nere eller har ingen lease ännu). DHCP är
	// det enda som kan ge kortet en adress utan att gissa ett subnät.
	return "dhcp", "", ""
}
