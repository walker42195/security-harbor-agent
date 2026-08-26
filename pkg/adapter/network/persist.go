package network

// Val av persistenslager.
//
// Att skriva ner gränssnittskonfigurationen så att den överlever en omstart
// (se paketkommentaren i netplan.go för varför) kan inte göras på ett enda
// sätt: vilket lager som ÄGER nätverket skiljer sig mellan distributionerna
// agenten installeras på. Skriver vi till fel lager blir filen antingen
// ignorerad — och vi är tillbaka i buggen där en adress bara lever i
// agentens minne — eller så börjar två managers slåss om samma kort.
//
// Därför detekteras lagret vid varje applicering och konfigurationen skrivs
// på det sätt en administratör själv hade gjort på just den maskinen:
//
//	Ubuntu (och Debian med netplan)   → /etc/netplan/90-security-harbor.yaml
//	Debian/RHEL med NetworkManager    → nmcli-profiler (security-harbor-<kort>)
//	systemd-networkd utan netplan     → /etc/systemd/network/05-security-harbor-*
//
// Ordningen är medveten. Netplan först: på Ubuntu är det det kanoniska
// lagret och det renderar SJÄLVT vidare till antingen networkd eller
// NetworkManager, så att gå runt det vore fel även när NetworkManager är
// igång. NetworkManager före rå networkd: kör NM så är det NM som äger
// korten oavsett om networkd råkar vara aktiv.
//
// Hittas inget av lagren faller vi tillbaka på enbart den imperativa
// `ip`-vägen — den fungerar direkt men överlever ingen omstart, så det
// rapporteras som en varning uppåt i stället för att tigas ihjäl.

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

// PersistBackend skriver gränssnittskonfiguration till det lager som äger
// nätverket på maskinen, och får den tillämpad på ett enskilt kort.
type PersistBackend interface {
	// Name är lagrets namn, för loggning och felmeddelanden.
	Name() string
	// Write skriver HELA konfigurationen (alla gränssnitt) och returnerar
	// true om något faktiskt ändrades sedan förra gången.
	Write(ctx context.Context, ifaces []config.Interface) (bool, error)
	// Reconfigure tillämpar den skrivna konfigurationen på ETT kort.
	// Medvetet per kort: en ändring på ett gränssnitt ska aldrig bryta
	// länken på de andra.
	Reconfigure(ctx context.Context, device string) error
	// Renew begär en ny DHCP-lease för ett kort ("förnya IP" i GUI:t).
	Renew(ctx context.Context, device string) error
}

type netplanBackend struct{}

func (b *netplanBackend) Name() string { return "netplan" }

// DetectPersistBackend väljer persistenslager enligt ordningen i
// paketkommentaren ovan. Returnerar nil om inget känt lager finns.
func DetectPersistBackend() PersistBackend {
	if commandExists("netplan") && (systemdUnitActive("systemd-networkd") || systemdUnitActive("NetworkManager")) {
		return &netplanBackend{}
	}
	if systemdUnitActive("NetworkManager") && commandExists("nmcli") {
		return &networkManagerBackend{}
	}
	if systemdUnitActive("systemd-networkd") {
		return &networkdBackend{}
	}
	return nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// systemdUnitActive svarar på om en unit är igång. `systemctl is-active`
// returnerar exit != 0 för allt utom "active", så utskriften — inte
// felkoden — är det som avgör.
func systemdUnitActive(unit string) bool {
	out, _ := exec.Command("systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out)) == "active"
}

// deviceNameFor härleder Linux-enhetsnamnet för ett gränssnitt. För VLAN
// byggs det av förälder + id (samma normalisering som ApplyInterfaceConfig
// gör) i stället för att lita på Device-fältet, som kan vara inaktuellt om
// VLAN:en flyttats till ett annat fysiskt kort.
func deviceNameFor(iface config.Interface) string {
	if iface.VLANID > 0 && iface.Parent != "" {
		return fmt.Sprintf("%s.%d", iface.Parent, iface.VLANID)
	}
	return iface.Device
}

// reloadAndReconfigure tillämpar systemd-networkd-konfiguration på ETT kort.
// Delas av netplan- och networkd-backendarna: netplan renderar bara vidare
// till networkd, så själva tillämpningen är identisk.
//
// Medvetet inte `netplan apply` eller `systemctl restart systemd-networkd`,
// som båda rör ALLA kort samtidigt — en ändring på ett gränssnitt ska aldrig
// bryta länken på de andra (samma princip som engine.applyInterfaces bygger
// på). `networkctl reload` läser in de genererade filerna, `reconfigure`
// tillämpar dem på kortet; reload är billig och idempotent.
func reloadAndReconfigure(ctx context.Context, device string) error {
	if device == "" {
		return nil
	}
	if !safeDeviceName.MatchString(device) {
		return fmt.Errorf("ogiltigt enhetsnamn %q", device)
	}
	if out, err := exec.CommandContext(ctx, "networkctl", "reload").CombinedOutput(); err != nil {
		return fmt.Errorf("networkctl reload: %w - %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "networkctl", "reconfigure", device).CombinedOutput(); err != nil {
		return fmt.Errorf("networkctl reconfigure %s: %w - %s", device, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Renew för de networkd-baserade lagren: `networkctl renew` ber om en ny
// lease utan att röra kortets övriga konfiguration.
func networkctlRenew(ctx context.Context, device string) error {
	if !safeDeviceName.MatchString(device) {
		return fmt.Errorf("ogiltigt enhetsnamn %q", device)
	}
	if out, err := exec.CommandContext(ctx, "networkctl", "renew", device).CombinedOutput(); err != nil {
		return fmt.Errorf("networkctl renew %s: %w - %s", device, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (b *netplanBackend) Renew(ctx context.Context, device string) error {
	return networkctlRenew(ctx, device)
}

func (b *networkdBackend) Renew(ctx context.Context, device string) error {
	return networkctlRenew(ctx, device)
}
