// Package dns genererar Unbound-konfiguration för brandväggens lokala
// DNS-resolver och domänfiltrering (Fas 6). Domänblocklistan (som kan
// innehålla hundratusentals poster, t.ex. StevenBlack hosts) hålls ALDRIG
// i den deklarativa JSON-configen — den skrivs till en egen include-fil
// som Unbound läser direkt, se ApplyConfig.
package dns

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

type Adapter struct {
	// dir är katalogen där unbound.conf.d-filerna skrivs, normalt
	// /etc/unbound/security-harbor.d.
	dir string
}

// Arch/de flesta distros default-installerar unbound.conf med
// `include: "/etc/unbound/unbound.conf.d/*.conf"` redan från paketet, så
// att skriva hit kräver ingen ändring av systemets bas-unbound.conf.
const defaultDir = "/etc/unbound/unbound.conf.d"

func NewAdapter(dir string) *Adapter {
	if dir == "" {
		dir = defaultDir
	}
	return &Adapter{dir: dir}
}

// GenerateServerConfig renderar huvudkonfigurationen (server: + forward-zone:).
// Domänerna som ska blockeras skrivs INTE här, utan i en separat include-fil
// (blocklistPath, se blocklistFilename) för att hålla huvudfilen läsbar och
// snabb att skriva om vid varje Apply oavsett blocklistans storlek.
func GenerateServerConfig(cfg *config.Config, blocklistPath string) (string, error) {
	if cfg.DNS == nil || !cfg.DNS.Enabled {
		return "", nil
	}
	d := cfg.DNS

	var lanNetworks []string
	var lanIPs []string
	seenNet, seenIP := map[string]bool{}, map[string]bool{}
	for _, iface := range cfg.Interfaces {
		if !iface.Enabled || iface.Zone == "WAN" || iface.IPv4 == "" {
			continue
		}
		ip, ipNet, err := net.ParseCIDR(iface.IPv4)
		if err != nil {
			continue
		}
		if netStr := ipNet.String(); !seenNet[netStr] {
			seenNet[netStr] = true
			lanNetworks = append(lanNetworks, netStr)
		}
		if ipStr := ip.String(); !seenIP[ipStr] {
			seenIP[ipStr] = true
			lanIPs = append(lanIPs, ipStr)
		}
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "server:\n")
	// Bind ENDAST till LAN-interfacens specifika IP:n, INTE 0.0.0.0.
	// systemd-resolved (Ubuntu/Debian) äger redan loopback-stubben
	// (127.0.0.53/.54:53), och en wildcard-bind kolliderar med den
	// ("Address already in use") — upptäckt vid skarp testning mot
	// 10.0.0.163 2026-08-18. Att bara binda LAN-IP:er är dessutom
	// arkitekturellt rätt: en brandväggs DNS-resolver ska svara på
	// LAN-sidan, inte på loopback eller WAN.
	for _, ip := range lanIPs {
		fmt.Fprintf(&b, "    interface: %s\n", ip)
	}
	fmt.Fprintf(&b, "    port: 53\n")
	fmt.Fprintf(&b, "    do-ip4: yes\n")
	fmt.Fprintf(&b, "    do-udp: yes\n")
	fmt.Fprintf(&b, "    do-tcp: yes\n")
	fmt.Fprintf(&b, "    hide-identity: yes\n")
	fmt.Fprintf(&b, "    hide-version: yes\n")
	fmt.Fprintf(&b, "    access-control: 127.0.0.0/8 allow\n")
	for _, net := range lanNetworks {
		fmt.Fprintf(&b, "    access-control: %s allow\n", net)
	}
	fmt.Fprintf(&b, "    access-control: 0.0.0.0/0 refuse\n")
	if hasAnyBlocklistSource(d) && blocklistPath != "" {
		fmt.Fprintf(&b, "    include: \"%s\"\n", blocklistPath)
	}
	// tls-cert-bundle (server:-klausul-option) måste anges explicit — utan
	// den har Unbound inga tillförlitliga CA-ankare alls och avvisar VARJE
	// upstream-certifikat (loggat missvisande som "self-signed certificate
	// in certificate chain" även för ett helt legitimt Cloudflare/Quad9-
	// cert). Upptäckt vid skarp testning mot 10.0.0.163 2026-08-18
	// (Debian/Ubuntu-sökväg).
	if d.DoTEnabled {
		fmt.Fprintf(&b, "    tls-cert-bundle: \"/etc/ssl/certs/ca-certificates.crt\"\n")
	}
	fmt.Fprintf(&b, "\n")

	if len(d.UpstreamServers) > 0 {
		fmt.Fprintf(&b, "forward-zone:\n")
		fmt.Fprintf(&b, "    name: \".\"\n")
		if d.DoTEnabled {
			fmt.Fprintf(&b, "    forward-tls-upstream: yes\n")
			for _, up := range d.UpstreamServers {
				host := d.DoTHostname
				if host == "" {
					host = up
				}
				fmt.Fprintf(&b, "    forward-addr: %s@853#%s\n", up, host)
			}
		} else {
			for _, up := range d.UpstreamServers {
				fmt.Fprintf(&b, "    forward-addr: %s\n", up)
			}
		}
	}

	return b.String(), nil
}

const blocklistFilename = "blocklist.conf"

// GenerateBlocklistConfig bygger include-filen med `local-zone`-direktiv
// för varje blockerad domän. CustomAllowedDomains (allowlist) skrivs EFTER
// blocklistan med `transparent`, vilket i Unbound gör att den mer
// specifika/senare posten vinner för exakt den domänen.
func GenerateBlocklistConfig(domains []string, cfg *config.Config) string {
	if cfg.DNS == nil {
		return ""
	}
	blocked := make(map[string]bool, len(domains)+len(cfg.DNS.CustomBlockedDomains))
	for _, d := range domains {
		blocked[normalizeDomain(d)] = true
	}
	for _, d := range cfg.DNS.CustomBlockedDomains {
		blocked[normalizeDomain(d)] = true
	}
	for _, d := range cfg.DNS.CustomAllowedDomains {
		delete(blocked, normalizeDomain(d))
	}

	// `local-zone:` är en server:-klausul-option — en inkluderad fil med
	// bara bara-local-zone-rader (utan ett eget `server:`-huvud) avvisas
	// av Unbound med "syntax error, is there no section start after an
	// include-toplevel directive perhaps" (upptäckt vid skarp testning
	// mot 10.0.0.163 2026-08-18).
	var b bytes.Buffer
	fmt.Fprintf(&b, "server:\n")
	for domain := range blocked {
		if domain == "" {
			continue
		}
		fmt.Fprintf(&b, "    local-zone: \"%s.\" always_nxdomain\n", domain)
	}
	for _, d := range cfg.DNS.CustomAllowedDomains {
		domain := normalizeDomain(d)
		if domain == "" {
			continue
		}
		fmt.Fprintf(&b, "    local-zone: \"%s.\" transparent\n", domain)
	}
	return b.String()
}

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}

// hasAnyBlocklistSource avgör om blocklist.conf ska skrivas/inkluderas
// alls — antingen minst en aktiverad automatisk källa (Fas 6, kan vara
// flera samtidigt) eller åtminstone en manuellt inmatad blockerad domän.
func hasAnyBlocklistSource(d *config.DNSConfig) bool {
	if len(d.CustomBlockedDomains) > 0 {
		return true
	}
	for _, src := range d.Blocklists {
		if src.Enabled {
			return true
		}
	}
	return false
}

// ApplyConfig skriver unbound.conf.d/*.conf och startar/stoppar/
// restartar unbound.service. domains är den cachade domänblocklistan (från
// pkg/threatfeed, hämtad separat — se Engine.applyBackends), inte något
// som lagras i config.Config.
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, domains []string, dryRun bool) error {
	unit := "unbound.service"

	if cfg.DNS == nil || !cfg.DNS.Enabled {
		if dryRun {
			return nil
		}
		_ = exec.CommandContext(ctx, "systemctl", "stop", unit).Run()
		return nil
	}

	blocklistPath := filepath.Join(a.dir, blocklistFilename)
	serverConf, err := GenerateServerConfig(cfg, blocklistPath)
	if err != nil {
		return fmt.Errorf("misslyckades generera Unbound-konfiguration: %w", err)
	}

	if dryRun {
		return nil
	}

	if err := os.MkdirAll(a.dir, 0755); err != nil {
		return fmt.Errorf("misslyckades skapa katalog %s: %w", a.dir, err)
	}
	if err := os.WriteFile(filepath.Join(a.dir, "security-harbor.conf"), []byte(serverConf), 0644); err != nil {
		return fmt.Errorf("misslyckades skriva security-harbor.conf: %w", err)
	}
	if hasAnyBlocklistSource(cfg.DNS) {
		blocklistConf := GenerateBlocklistConfig(domains, cfg)
		if err := os.WriteFile(filepath.Join(a.dir, blocklistFilename), []byte(blocklistConf), 0644); err != nil {
			return fmt.Errorf("misslyckades skriva %s: %w", blocklistFilename, err)
		}
	}

	if out, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart %s misslyckades: %w - output: %s", unit, err, string(out))
	}

	return nil
}
