package network

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

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

// PopulateDynamicIPs populerar konfigurationens DHCP-gränssnitt med deras
// aktiva Linux IP-adress OCH default gateway. Statiska gränssnitt rörs
// inte (deras IPv4/Gateway kommer redan från den deklarativa configen).
//
// cfg.Interfaces kopieras till en ny slice innan mutation — cfg kan komma
// direkt från store.GetRunningConfig() via en shallow `cfgCopy := *cfg` i
// API-handlern, och en shallow struct-kopia delar fortfarande samma
// underliggande []Interface-array. Att skriva i den hade tyst mutaterat
// den RIKTIGA lagrade running-configen (inte bara svarskopian) varje gång
// någon läste /api/v1/config/running.
func (a *Adapter) PopulateDynamicIPs(cfg *config.Config) {
	if cfg == nil {
		return
	}
	discovered, err := a.DiscoverInterfaces()
	if err != nil {
		return
	}

	discMap := make(map[string][]string)
	for _, d := range discovered {
		discMap[d.Name] = d.IPs
	}

	ifaces := make([]config.Interface, len(cfg.Interfaces))
	copy(ifaces, cfg.Interfaces)

	for i := range ifaces {
		iface := &ifaces[i]
		if iface.AddressType == "dhcp" || iface.IPv4 == "" {
			if ips, ok := discMap[iface.Device]; ok {
				for _, ip := range ips {
					if strings.Contains(ip, ".") && !strings.HasPrefix(ip, "127.") {
						iface.IPv4 = ip
						break
					}
				}
			}
		}
		// Bara WAN-gränssnittet har en meningsfull default-gateway. Interna
		// gränssnitt (LAN/VLAN) ska aldrig visa/registrera en gateway även om
		// de av misstag råkat plocka upp en från en intern DHCP-server —
		// brandväggens väg ut går uteslutande via WAN (se applyInterface).
		if iface.AddressType == "dhcp" && strings.EqualFold(iface.Zone, "WAN") {
			if gw := defaultGatewayFor(iface.Device); gw != "" {
				iface.Gateway = gw
			}
		}
	}
	cfg.Interfaces = ifaces
}

// defaultGatewayFor läser default-gatewayen för ett specifikt gränssnitt
// (relevant för WAN i "dhcp"-läge, där gatewayen kommer från ISP:ns
// DHCP-svar och inte finns i den deklarativa configen).
func defaultGatewayFor(device string) string {
	if device == "" {
		return ""
	}
	out, err := exec.Command("ip", "-4", "route", "show", "default", "dev", device).Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
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

	// 2. Manuellt satt MAC-adress ("MAC-kloning") och MTU.
	//
	// MÅSTE ske medan kortet är NERE: de flesta drivrutiner avvisar en
	// adressändring på ett uppe kort med EBUSY. Vi tar därför alltid ner
	// kortet först, sätter MAC:en, och låter steg 3 nedan ta upp det igen.
	// Kortet är nere i millisekunder och bara när en MAC faktiskt är
	// konfigurerad — sitter administratören på det kortet märks det inte.
	if mac := strings.TrimSpace(iface.MACAddress); mac != "" && !macAlreadySet(iface.Device, mac) {
		_ = exec.CommandContext(ctx, "ip", "link", "set", iface.Device, "down").Run()
		out, err := exec.CommandContext(ctx, "ip", "link", "set", "dev", iface.Device, "address", mac).CombinedOutput()
		if err != nil {
			// Inte ett hårt fel: kortet fungerar med sin brända adress, och
			// att fälla hela appliceringen (och därmed brandväggsreglerna)
			// för att en MAC-kloning nekades vore oproportionerligt. Vissa
			// virtuella kort tillåter helt enkelt inte ändringen.
			log.Printf("[NÄTVERK] kunde inte sätta MAC %s på %s: %v - %s", mac, iface.Device, err, strings.TrimSpace(string(out)))
		} else {
			log.Printf("[NÄTVERK] %s använder manuellt satt MAC-adress %s", iface.Device, mac)
		}
	}
	if iface.MTU > 0 {
		_ = exec.CommandContext(ctx, "ip", "link", "set", "dev", iface.Device, "mtu", strconv.Itoa(iface.MTU)).Run()
	}

	// 3. Sätt interface UP eller DOWN
	state := "up"
	if !iface.Enabled {
		state = "down"
	}
	cmdState := exec.CommandContext(ctx, "ip", "link", "set", iface.Device, state)
	_ = cmdState.Run()

	// 4. Om statisk IPv4 är angiven, tilldela IP-adressen
	if iface.Enabled && iface.AddressType == "static" && iface.IPv4 != "" {
		// Flush gamla adresser först för att undvika konflikter
		_ = exec.CommandContext(ctx, "ip", "addr", "flush", "dev", iface.Device).Run()

		cmdAddr := exec.CommandContext(ctx, "ip", "addr", "add", iface.IPv4, "dev", iface.Device)
		out, err := cmdAddr.CombinedOutput()
		if err != nil && !strings.Contains(string(out), "File exists") {
			return fmt.Errorf("misslyckades sätta IP %s på %s: %w - %s", iface.IPv4, iface.Device, err, string(out))
		}
	} else if iface.Enabled && iface.AddressType == "dhcp" {
		// Ta bort kvarglömda STATISKA adresser innan dhclient körs.
		//
		// Buggen (rapporterad skarpt 2026-08-25): `ip addr flush` kördes BARA
		// i static-grenen ovan. Gick ett kort från statiskt till DHCP låg den
		// gamla statiska adressen kvar för alltid, och DHCP-adressen lades
		// till som en ANDRA adress på kortet. Administratören såg då sin
		// "gamla" IP fortsätta svara trots att den bytts i GUI:t.
		//
		// Vi flushar medvetet INTE allt: den nuvarande DHCP-leasen ska leva
		// kvar tills dhclient (som körs asynkront nedan) hunnit svara,
		// annars står kortet utan adress i flera sekunder och en
		// administratör som sitter på det kortet tappar sin session. Därför
		// tas bara PERMANENTA (icke-dynamiska) adresser bort — det är exakt
		// de statiska rester som inte hör hemma på ett DHCP-kort.
		removeStaticAddresses(ctx, iface.Device)
		// Om gränssnittet är satt till DHCP, trigga dhclient. "-1" gör ETT
		// försök och avslutar om ingen server svarar (annars hänger klienten
		// kvar för evigt på t.ex. en VLAN utan DHCP-server), och en
		// timeout-context ser till att processen aldrig blir kvarglömd.
		//
		// ENDAST WAN-gränssnittet ska ta emot en default-rutt (och DNS) från
		// DHCP. Interna gränssnitt (LAN/VLAN/servrar) i DHCP-läge ska bara
		// hämta sin IP-adress — aldrig installera en default-rutt, för då får
		// brandväggen flera konkurrerande default-rutter och egress-valet blir
		// slumpartat: trafik kan lämna fel kort, förbi masquerade och
		// LAN→WAN-policyn (som matchar oifname = WAN-kortet), och fastnar då på
		// Default Deny. Interna gränssnitt kör därför en begränsad
		// dhclient-konfig som inte begär routers/DNS, och en ev. default-rutt
		// via kortet tas bort direkt efteråt (bälte och hängslen, ifall
		// DHCP-servern skickar routers ändå).
		isWAN := strings.EqualFold(iface.Zone, "WAN")
		go func(device string, isWAN bool) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			runDHClientOnce(ctx, device, isWAN)
		}(iface.Device, isWAN)
	}

	// En brandvägg får ha default-rutt ENDAST via WAN. Ett internt gränssnitt
	// kan ha en kvarglömd default-rutt — t.ex. ett kort som tidigare var DHCP
	// och nu är statiskt (den gamla "proto dhcp"-rutten flushas inte av `ip
	// addr flush`). Ta bort ev. default-rutt via icke-WAN-gränssnitt synkront
	// här; DHCP-fallet hanteras dessutom inne i goroutinen ovan efter att
	// dhclient hunnit installera sin rutt.
	if iface.Enabled && !strings.EqualFold(iface.Zone, "WAN") {
		// Kan finnas flera default-rutter via samma kort; loopa tills slut.
		for i := 0; i < 8; i++ {
			if err := exec.CommandContext(ctx, "ip", "route", "del", "default", "dev", iface.Device).Run(); err != nil {
				break
			}
		}
	}

	return nil
}

// removeStaticAddresses tar bort alla PERMANENTA IPv4-adresser på ett kort
// men lämnar DHCP-tilldelade (dynamiska) adresser orörda. Används när ett
// kort körs i DHCP-läge: då är en permanent adress per definition en rest
// från en tidigare statisk konfiguration.
//
// `ip -4 addr show dev X` markerar DHCP-adresser med "dynamic"; allt annat
// är permanent. Vi kan inte använda `ip addr flush` här eftersom den tar
// bort ÄVEN den aktiva leasen och lämnar kortet utan adress tills dhclient
// svarat — det skulle koppla ner administratören mitt i en applicering.
// macAlreadySet undviker att i onödan ta ner kortet vid varje applicering.
// Utan kontrollen hade varenda "Applicera" — även en som bara rör en
// policyrad — kort brutit länken på ett kort med klonad MAC.
func macAlreadySet(device, want string) bool {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return false
	}
	wantHW, err := net.ParseMAC(want)
	if err != nil {
		return false
	}
	return bytes.Equal(iface.HardwareAddr, wantHW)
}

func removeStaticAddresses(ctx context.Context, device string) {
	out, err := exec.CommandContext(ctx, "ip", "-4", "-o", "addr", "show", "dev", device).Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" || strings.Contains(line, "dynamic") {
			continue // tom rad, eller en aktiv DHCP-lease som ska vara kvar
		}
		fields := strings.Fields(line)
		// Format: "3: ens19    inet 10.0.0.9/24 scope global ens19\..."
		for i, f := range fields {
			if f != "inet" || i+1 >= len(fields) {
				continue
			}
			cidr := fields[i+1]
			log.Printf("[NÄTVERK] %s är i DHCP-läge — tar bort kvarglömd statisk adress %s", device, cidr)
			_ = exec.CommandContext(ctx, "ip", "addr", "del", cidr, "dev", device).Run()
			break
		}
	}
}

// runDHClientOnce kör dhclient EN gång mot ett gränssnitt — utbruten ur
// ApplyInterfaceConfig (Fas 13-arvet) så att samma logik även kan triggas
// manuellt via RenewDHCP (en "förnya"-knapp i GUI:t, 2026-08-24) utan att
// gå via en hel gränssnittsapplicering. Anroparen ansvarar för context/
// timeout och ev. att köra detta i en egen goroutine.
func runDHClientOnce(ctx context.Context, device string, isWAN bool) {
	if isWAN {
		_ = exec.CommandContext(ctx, "dhclient", "-1", "-v", device).Run()
		return
	}
	if confPath, cleanup, err := writeInternalDHClientConf(); err == nil {
		defer cleanup()
		_ = exec.CommandContext(ctx, "dhclient", "-1", "-v", "-cf", confPath, device).Run()
	} else {
		_ = exec.CommandContext(ctx, "dhclient", "-1", "-v", device).Run()
	}
	_ = exec.CommandContext(ctx, "ip", "route", "del", "default", "dev", device).Run()
}

// RenewDHCP kör om DHCP-förhandlingen för ETT gränssnitt på begäran (en
// "förnya IP"-knapp i GUI:t) — samma dhclient-anrop som redan görs
// automatiskt när ett gränssnitt sätts till DHCP-läge, men körs SYNKRONT
// här (anroparen väntar på svaret) i stället för i en bakgrunds-goroutine,
// eftersom det här är en explicit, av administratören begärd åtgärd som
// ska ge tydlig återkoppling (lyckades/misslyckades), inte en tyst
// bakgrundsprocess.
func (a *Adapter) RenewDHCP(ctx context.Context, device string, isWAN bool) error {
	if device == "" {
		return fmt.Errorf("gränssnittsenhet saknas")
	}
	runDHClientOnce(ctx, device, isWAN)
	return nil
}

// writeInternalDHClientConf skriver en tillfällig dhclient-konfiguration som
// bara begär adressrelaterade optioner (subnätmask, broadcast, MTU, hostname)
// — INTE routers eller domän/DNS. Används för interna DHCP-gränssnitt så att
// de hämtar en IP-adress utan att installera en default-rutt eller skriva
// över brandväggens /etc/resolv.conf. Anroparen kör cleanup() när dhclient är
// klar för att ta bort filen.
func writeInternalDHClientConf() (string, func(), error) {
	f, err := os.CreateTemp("", "sh-dhclient-internal-*.conf")
	if err != nil {
		return "", nil, err
	}
	// När en egen `request`-lista anges ERSÄTTER den dhclients default-lista,
	// så routers och domain-name-servers utelämnas helt.
	const conf = "request subnet-mask, broadcast-address, time-offset, interface-mtu, host-name;\n"
	if _, err := f.WriteString(conf); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", nil, err
	}
	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}

// DeleteVLANInterface tar bort ett VLAN-subinterface från Linux (`ip link
// del`). Används när en VLAN flyttas till ett annat fysiskt kort: det gamla
// subinterfacet (t.ex. ens19.9) måste rivas innan det nya (ens20.9) skapas,
// annars ligger det kvar och fångar trafik på fel kort. Ett redan
// försvunnet interface är inte ett fel (idempotent).
func (a *Adapter) DeleteVLANInterface(ctx context.Context, device string) error {
	if device == "" {
		return nil
	}
	if _, err := net.InterfaceByName(device); err != nil {
		// Finns inte längre — inget att göra.
		return nil
	}
	cmd := exec.CommandContext(ctx, "ip", "link", "del", device)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("misslyckades ta bort VLAN %s: %w - %s", device, err, string(out))
	}
	return nil
}

// DeconfigureInterface av-konfigurerar ett gränssnitt som tagits bort ur
// konfigurationen: tar bort dess IP-adresser och ev. default-rutt, utan att
// riva själva (fysiska) enheten — den kan ligga kvar i hypervisorn tills
// användaren tar bort den där. Idempotent (ett redan försvunnet gränssnitt är
// inget fel). Används av engine.applyInterfaces för borttagna icke-VLAN-kort;
// borttagna VLAN-subinterface rivs helt via DeleteVLANInterface i stället.
func (a *Adapter) DeconfigureInterface(ctx context.Context, device string) error {
	if device == "" {
		return nil
	}
	if _, err := net.InterfaceByName(device); err != nil {
		// Finns inte längre — inget att göra.
		return nil
	}
	_ = exec.CommandContext(ctx, "ip", "addr", "flush", "dev", device).Run()
	// Ta bort ev. default-rutt(er) via kortet så det inte fortsätter påverka
	// egress efter att det plockats bort ur configen.
	for i := 0; i < 8; i++ {
		if err := exec.CommandContext(ctx, "ip", "route", "del", "default", "dev", device).Run(); err != nil {
			break
		}
	}
	return nil
}

// ApplyStaticRoute installerar (eller uppdaterar) en statisk rutt på Linux.
// Använder "ip route replace" i stället för "add" — idempotent, så samma
// rutt kan appliceras om vid varje Apply utan att först behöva kontrollera
// om den redan finns (skiljer sig från interface-adresser ovan, som flushas
// explicit före "addr add" av samma anledning).
func (a *Adapter) ApplyStaticRoute(ctx context.Context, r config.StaticRoute) error {
	if r.Network == "" || r.Gateway == "" {
		return fmt.Errorf("rutt saknar nät eller gateway")
	}
	args := []string{"route", "replace", r.Network, "via", r.Gateway}
	if r.Interface != "" {
		args = append(args, "dev", r.Interface)
	}
	cmd := exec.CommandContext(ctx, "ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("misslyckades sätta rutt %s via %s: %w - %s", r.Network, r.Gateway, err, string(out))
	}
	return nil
}

// DeleteStaticRoute tar bort en statisk rutt. Idempotent: en rutt som redan
// saknas (t.ex. för att gränssnittet den gick via försvann, eller den redan
// togs bort av ett tidigare anrop) är inte ett fel.
func (a *Adapter) DeleteStaticRoute(ctx context.Context, r config.StaticRoute) error {
	if r.Network == "" {
		return nil
	}
	args := []string{"route", "del", r.Network}
	if r.Gateway != "" {
		args = append(args, "via", r.Gateway)
	}
	if r.Interface != "" {
		args = append(args, "dev", r.Interface)
	}
	cmd := exec.CommandContext(ctx, "ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such process") {
		return fmt.Errorf("misslyckades ta bort rutt %s: %w - %s", r.Network, err, string(out))
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
