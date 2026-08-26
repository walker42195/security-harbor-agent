// Package ntp gör brandväggen till NTP-server för de interna näten.
//
// Enheter i DMZ och på IoT-VLAN behöver rätt tid — certifikatvalidering,
// TLS-handskakningar och loggarnas tillförlitlighet hänger på den — men de
// ska inte behöva nå ut till internet för att få den. Med brandväggen som
// NTP-server räcker det att öppna UDP 123 mot den, i stället för mot valfri
// tidsserver på internet.
//
// Implementationen skriver en egen fil i chronys confdir i stället för att
// röra chrony.conf: distributionens fil ägs av paketet och skrivs över vid
// uppgradering. Chrony agerar server så fort den har minst ett "allow" — den
// klientkonfiguration som redan finns lämnas orörd.
package ntp

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/svc"
	"github.com/walker42195/security-harbor-agent/pkg/config"
)

const (
	defaultDir  = "/etc/chrony/conf.d"
	confName    = "security-harbor.conf"
	serviceUnit = "chrony.service"
)

type Adapter struct{ dir string }

func NewAdapter(dir string) *Adapter {
	if dir == "" {
		dir = defaultDir
	}
	return &Adapter{dir: dir}
}

// GenerateConfig renderar chrony-snutten.
//
// Näten härleds ur de aktiverade interna gränssnittens egna subnät i stället
// för att vara en egen lista att hålla i synk. Lägger man till ett VLAN får
// det NTP automatiskt; tar man bort det försvinner behörigheten med.
//
// WAN utelämnas alltid. En öppen NTP-server mot internet är ett klassiskt
// förstärkningsverktyg för DDoS-attacker (NTP amplification) — den ska aldrig
// kunna hamna där av misstag.
func GenerateConfig(cfg *config.Config) string {
	if cfg == nil || cfg.NTP == nil || !cfg.NTP.Enabled {
		return ""
	}

	seen := map[string]bool{}
	var networks []string
	for _, iface := range cfg.Interfaces {
		if !iface.Enabled || strings.EqualFold(iface.Zone, "WAN") || iface.IPv4 == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(iface.IPv4)
		if err != nil {
			continue
		}
		if s := ipNet.String(); !seen[s] {
			seen[s] = true
			networks = append(networks, s)
		}
	}
	sort.Strings(networks) // stabil utskrift → ingen onödig omstart

	var b bytes.Buffer
	b.WriteString("# Skriven av Security Harbor-agenten - redigera inte för hand.\n")
	b.WriteString("# Gör brandväggen till NTP-server för de interna näten.\n")
	if len(networks) == 0 {
		// Inga interna nät: skriv en tom (men kommenterad) fil hellre än att
		// lämna en gammal kvar med behörigheter som inte längre gäller.
		b.WriteString("# Inga interna gränssnitt med statisk adress - ingen allow.\n")
		return b.String()
	}
	for _, n := range networks {
		fmt.Fprintf(&b, "allow %s\n", n)
	}
	// Servera tid även innan chrony själv synkat mot en uppström. Utan detta
	// vägrar den svara efter en omstart tills den hittat en källa, och
	// klienterna står utan tid precis när de behöver den som mest.
	if cfg.NTP.ServeWhenUnsynced {
		b.WriteString("local stratum 10\n")
	}
	return b.String()
}

// ApplyConfig skriver konfigurationen och startar om chrony BARA när något
// faktiskt ändrats (se pkg/adapter/svc) — en omstart av tidssynkroniseringen
// mitt i drift är onödig och kan ge ett hopp i klockan.
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, dryRun bool) error {
	content := GenerateConfig(cfg)
	path := filepath.Join(a.dir, confName)

	if dryRun {
		return nil
	}

	// Avstängd funktion: ta bort filen så chrony slutar servera.
	if content == "" {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("kunde inte ta bort %s: %w", path, err)
		}
		if _, err := svc.RestartIfNeeded(ctx, serviceUnit, true); err != nil {
			return err
		}
		return nil
	}

	if err := os.MkdirAll(a.dir, 0o755); err != nil {
		return fmt.Errorf("kunde inte skapa %s: %w", a.dir, err)
	}
	changed, err := svc.WriteIfChanged(path, []byte(content))
	if err != nil {
		return fmt.Errorf("kunde inte skriva %s: %w", path, err)
	}
	restarted, err := svc.RestartIfNeeded(ctx, serviceUnit, changed)
	if err != nil {
		return err
	}
	if !restarted {
		log.Printf("[NTP] konfigurationen oförändrad - hoppar över omstart av %s", serviceUnit)
	}
	return nil
}
