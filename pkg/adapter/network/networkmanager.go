package network

// NetworkManager-backend (nmcli).
//
// Används på installationer där NetworkManager äger korten — typiskt Debian
// och RHEL-derivat. Agenten skapar en egen anslutningsprofil per gränssnitt,
// döpt "security-harbor-<kort>", och håller den uppdaterad. Profilerna är
// vanliga NM-profiler: administratören ser dem i `nmcli connection show` och
// i nmtui precis som om de hade skapats för hand.
//
// Två NM-egenskaper gör tungt arbete här och motsvarar exakt de garantier
// netplan-backenden ger med dhcp4-overrides:
//
//	ipv4.never-default yes   — kortet installerar ALDRIG en default-rutt,
//	                           vare sig den kommer från DHCP eller är satt
//	                           statiskt. Sätts på allt utom WAN.
//	ipv4.ignore-auto-dns yes — DHCP-svarets DNS-servrar skriver inte över
//	                           brandväggens egen resolver.
//
// Utan dem får en brandvägg med DHCP på ett internt kort konkurrerande
// default-rutter och ett slumpartat egress-val — samma fel som beskrivs i
// paketkommentaren i netplan.go.

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

type networkManagerBackend struct{}

func (b *networkManagerBackend) Name() string { return "NetworkManager" }

// nmProfileName är namnet på den profil agenten äger för ett kort. Prefixet
// gör den identifierbar: allt som heter så här är vårt och skrivs över,
// medan administratörens egna profiler lämnas ifred.
func nmProfileName(device string) string {
	return "security-harbor-" + device
}

// Write synkroniserar en NM-profil per gränssnitt. Till skillnad från de
// filbaserade backendarna finns ingen "hela konfigurationen"-fil att jämföra
// mot, så ändringsdetekteringen görs per profil: nuvarande värden läses ut
// med `nmcli -t connection show` och jämförs med de önskade. Det är vad som
// gör att en applicering som inte rör nätverket inte heller river igång
// korten.
func (b *networkManagerBackend) Write(ctx context.Context, ifaces []config.Interface) (bool, error) {
	changed := false
	for _, iface := range ifaces {
		device := deviceNameFor(iface)
		if device == "" {
			continue
		}
		if !safeDeviceName.MatchString(device) {
			return changed, fmt.Errorf("gränssnitt %q har ett ogiltigt enhetsnamn", device)
		}

		isVLAN := iface.VLANID > 0 && iface.Parent != ""
		if isVLAN && !iface.Enabled {
			// Avstängd VLAN: ta bort profilen helt så att kortet inte
			// återskapas vid boot. Samma innebörd som att utelämna den ur
			// netplan-filen.
			if b.profileExists(ctx, device) {
				_ = b.run(ctx, "connection", "delete", nmProfileName(device))
				changed = true
			}
			continue
		}

		settings, err := nmSettingsFor(iface, device, isVLAN)
		if err != nil {
			return changed, err
		}

		if !b.profileExists(ctx, device) {
			args := []string{"connection", "add", "con-name", nmProfileName(device)}
			if isVLAN {
				args = append(args, "type", "vlan", "dev", iface.Parent, "id", fmt.Sprintf("%d", iface.VLANID))
			} else {
				args = append(args, "type", "ethernet", "ifname", device)
			}
			// `save yes` gör profilen persistent på disk direkt.
			args = append(args, "save", "yes")
			if err := b.run(ctx, args...); err != nil {
				return changed, fmt.Errorf("kunde inte skapa NM-profil för %s: %w", device, err)
			}
			changed = true
		}

		dirty, err := b.applySettings(ctx, device, settings)
		if err != nil {
			return changed, err
		}
		if dirty {
			changed = true
		}
	}
	return changed, nil
}

// nmSettingsFor översätter ett gränssnitt till NM-egenskaper. Ordningen i
// kartan spelar ingen roll — nmcli tar dem som fristående key/value-par.
func nmSettingsFor(iface config.Interface, device string, isVLAN bool) (map[string]string, error) {
	isWAN := strings.EqualFold(iface.Zone, "WAN")
	s := map[string]string{
		"connection.autoconnect": boolYesNo(iface.Enabled),
		// Vinn över NM:s egen auto-skapade "Wired connection N" för kortet.
		"connection.autoconnect-priority": "100",
		// IPv6 lämnas avstängt: modellen har inga IPv6-fält, och en
		// RA-inlärd default-rutt via ett internt kort ger samma
		// egress-problem som en DHCP-inlärd.
		"ipv6.method": "disabled",
		// ALDRIG default-rutt eller DHCP-DNS via annat än WAN.
		"ipv4.never-default":   boolYesNo(!isWAN),
		"ipv4.ignore-auto-dns": boolYesNo(!isWAN),
	}

	if iface.MTU > 0 {
		if isVLAN {
			s["vlan.mtu"] = fmt.Sprintf("%d", iface.MTU)
		} else {
			s["802-3-ethernet.mtu"] = fmt.Sprintf("%d", iface.MTU)
		}
	}
	if mac := strings.TrimSpace(iface.MACAddress); mac != "" && !isVLAN {
		if !safeMAC.MatchString(mac) {
			return nil, fmt.Errorf("gränssnitt %q har en ogiltig MAC-adress %q", device, mac)
		}
		s["802-3-ethernet.cloned-mac-address"] = mac
	}

	if iface.AddressType == "static" && iface.IPv4 != "" {
		if !safeIPv4CIDR.MatchString(iface.IPv4) {
			return nil, fmt.Errorf("gränssnitt %q har en ogiltig IPv4-adress %q (ska vara t.ex. 10.0.0.9/24)", device, iface.IPv4)
		}
		s["ipv4.method"] = "manual"
		s["ipv4.addresses"] = iface.IPv4
		gw := strings.TrimSpace(iface.Gateway)
		if isWAN && gw != "" {
			if !safeIP.MatchString(gw) {
				return nil, fmt.Errorf("gränssnitt %q har en ogiltig gateway %q", device, gw)
			}
			s["ipv4.gateway"] = gw
		} else {
			// Tom sträng nollställer egenskapen i nmcli. Interna kort får
			// aldrig en gateway, ens om configen råkat få ett värde i fältet.
			s["ipv4.gateway"] = ""
		}
		if isWAN {
			s["ipv4.dns"] = strings.Join(sanitizedDNS(iface), ",")
		} else {
			s["ipv4.dns"] = ""
		}
	} else {
		s["ipv4.method"] = "auto"
		// Statiska rester från ett tidigare läge måste bort, annars ligger de
		// kvar som extra adresser vid sidan om DHCP-leasen.
		s["ipv4.addresses"] = ""
		s["ipv4.gateway"] = ""
		s["ipv4.dns"] = ""
	}
	return s, nil
}

// sanitizedDNS plockar ut giltiga DNS-adresser. Ogiltiga hoppas över i
// stället för att fälla appliceringen: fältet är fritext i GUI:t, och en
// felstavad DNS-server ska inte kunna hindra att brandväggsreglerna läggs på.
func sanitizedDNS(iface config.Interface) []string {
	var out []string
	for _, ns := range iface.DNSServers {
		ns = strings.TrimSpace(ns)
		if safeIP.MatchString(ns) {
			out = append(out, ns)
		}
	}
	return out
}

// applySettings sätter bara de egenskaper som faktiskt skiljer sig från vad
// profilen redan har, och rapporterar om något ändrades.
func (b *networkManagerBackend) applySettings(ctx context.Context, device string, want map[string]string) (bool, error) {
	current := b.profileValues(ctx, device, want)

	var args []string
	for key, value := range want {
		if cur, ok := current[key]; ok && nmValueEqual(cur, value) {
			continue
		}
		args = append(args, key, value)
	}
	if len(args) == 0 {
		return false, nil
	}

	full := append([]string{"connection", "modify", nmProfileName(device)}, args...)
	if err := b.run(ctx, full...); err != nil {
		return false, fmt.Errorf("kunde inte uppdatera NM-profil för %s: %w", device, err)
	}
	return true, nil
}

// nmValueEqual jämför ett värde som nmcli RAPPORTERAR med det vi vill sätta.
// Utläsningen är inte alltid identisk med inmatningen: en tom egenskap kommer
// tillbaka som "--", och adresser kan få efterföljande blanksteg. Utan den
// här normaliseringen hade varje applicering sett tomma fält som "ändrade"
// och skrivit om profilen i onödan — vilket i sin tur hade rivit upp kortet.
func nmValueEqual(current, want string) bool {
	current = strings.TrimSpace(current)
	if current == "--" {
		current = ""
	}
	return current == strings.TrimSpace(want)
}

// profileValues läser ut nuvarande värden för de efterfrågade egenskaperna.
// `-t -f <fält>` ger en rad per fält på formen "nyckel:värde"; värdet kan
// självt innehålla kolon (t.ex. MAC-adresser), så bara den FÖRSTA delas av.
func (b *networkManagerBackend) profileValues(ctx context.Context, device string, want map[string]string) map[string]string {
	fields := make([]string, 0, len(want))
	for key := range want {
		fields = append(fields, key)
	}
	out, err := exec.CommandContext(ctx, "nmcli", "-t", "-f", strings.Join(fields, ","),
		"connection", "show", nmProfileName(device)).Output()
	if err != nil {
		return nil
	}

	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		values[key] = value
	}
	return values
}

func (b *networkManagerBackend) profileExists(ctx context.Context, device string) bool {
	err := exec.CommandContext(ctx, "nmcli", "connection", "show", nmProfileName(device)).Run()
	return err == nil
}

// Reconfigure aktiverar profilen på kortet. `connection up` byter samtidigt
// bort en ev. konkurrerande profil (NM:s auto-skapade "Wired connection N")
// från kortet, vilket är just vad som behövs för att VÅR konfiguration ska
// vara den som gäller.
func (b *networkManagerBackend) Reconfigure(ctx context.Context, device string) error {
	if !safeDeviceName.MatchString(device) {
		return fmt.Errorf("ogiltigt enhetsnamn %q", device)
	}
	if !b.profileExists(ctx, device) {
		// Profilen har tagits bort (avstängd VLAN) — koppla ner kortet.
		_ = b.run(ctx, "device", "disconnect", device)
		return nil
	}
	if err := b.run(ctx, "connection", "up", nmProfileName(device)); err != nil {
		return fmt.Errorf("kunde inte aktivera NM-profilen för %s: %w", device, err)
	}
	return nil
}

func (b *networkManagerBackend) run(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "nmcli", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func boolYesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// Renew tvingar NM att förhandla om leasen. NM har ingen ren "renew"-
// operation för en profil; att aktivera den igen ger samma effekt.
func (b *networkManagerBackend) Renew(ctx context.Context, device string) error {
	return b.Reconfigure(ctx, device)
}
