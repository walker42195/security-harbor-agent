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
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/dhcp"
	"github.com/walker42195/security-harbor-agent/pkg/adapter/svc"
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
func GenerateServerConfig(cfg *config.Config, blocklistPath string, hostsPath string) (string, error) {
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
	if hostsPath != "" && (d.DHCPHostnameRegistration || len(d.StaticRecords) > 0) {
		fmt.Fprintf(&b, "    include: \"%s\"\n", hostsPath)
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

	// Recursive: Unbound gör full rekursiv upplösning mot rot-servrarna
	// (dess inbyggda default utan forward-zone) — ingen forward-zone
	// skrivs alls, UpstreamServers/DoT ignoreras helt.
	if !d.Recursive && len(d.UpstreamServers) > 0 {
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
		if !validDomain(domain) {
			continue
		}
		fmt.Fprintf(&b, "    local-zone: \"%s.\" always_nxdomain\n", domain)
	}
	for _, d := range cfg.DNS.CustomAllowedDomains {
		domain := normalizeDomain(d)
		if !validDomain(domain) {
			continue
		}
		fmt.Fprintf(&b, "    local-zone: \"%s.\" transparent\n", domain)
	}
	return b.String()
}

const hostsFilename = "hosts.conf"

// GenerateHostsConfig bygger include-filen med `local-data`-A-poster för
// dels manuellt inmatade StaticRecords, dels (om DHCPHostnameRegistration
// är på) värdnamn som DHCP-klienter skickat med i sin lease (Fas 6+).
// StaticRecords skrivs EFTER DHCP-posterna så att en manuell post alltid
// vinner om samma värdnamn råkar krocka (Unbound använder senaste
// definitionen för local-data på samma namn).
func GenerateHostsConfig(leases []dhcp.Lease, cfg *config.Config) string {
	if cfg.DNS == nil {
		return ""
	}
	d := cfg.DNS
	suffix := strings.Trim(d.LocalDomain, ".")

	var b bytes.Buffer
	fmt.Fprintf(&b, "server:\n")

	// appendSuffix styr om den lokala domänen (LocalDomain) ska hängas på ett
	// namn utan eget suffix. Sant för DHCP-auto-registrering (korta värdnamn
	// som ska hamna i den lokala zonen), FALSKT för manuella poster — där ska
	// namnet användas EXAKT som administratören skrev det, oavsett domän. Vill
	// man ha ett suffix på en manuell post skriver man hela namnet själv.
	writeRecord := func(hostname, ip string, appendSuffix bool) {
		hostname = strings.ToLower(strings.TrimSpace(hostname))
		hostname = strings.TrimSuffix(hostname, ".") // ev. absolut FQDN "namn."
		ip = strings.TrimSpace(ip)
		if hostname == "" || ip == "" {
			return
		}
		// Värdnamnet kan komma från en DHCP-lease, dvs. sättas av vilken
		// enhet som helst på nätet — och IP:t skrivs in i samma citerade
		// sträng. Båda måste valideras (se validDomain).
		if !validDomain(hostname) || net.ParseIP(ip) == nil {
			return
		}
		fqdn := hostname
		if appendSuffix && suffix != "" && !strings.HasSuffix(hostname, "."+suffix) && hostname != suffix {
			fqdn = hostname + "." + suffix
		}
		if !validDomain(fqdn) {
			return
		}
		fmt.Fprintf(&b, "    local-data: \"%s. IN A %s\"\n", fqdn, ip)
		fmt.Fprintf(&b, "    local-data-ptr: \"%s %s.\"\n", ip, fqdn)
	}

	if d.DHCPHostnameRegistration {
		for _, l := range leases {
			writeRecord(l.Hostname, l.IP, true) // korta DHCP-värdnamn → lokala zonen
		}
	}
	for _, rec := range d.StaticRecords {
		writeRecord(rec.Hostname, rec.IP, false) // manuella poster: exakt som angivet
	}

	return b.String()
}

// safeDomainPattern är en ALLOWLIST för allt som skrivs in i Unbounds
// konfiguration som ett domännamn (local-zone/local-data). Bara tecken som
// faktiskt får förekomma i ett värdnamn — inga citattecken, blanksteg eller
// radbrytningar.
//
// Kodgranskning 2026-08-25: normalizeDomain gjorde bara ToLower + trim, och
// värdet skrevs in i en CITERAD sträng: `local-zone: "%s." ...`. Ett
// citattecken bröt alltså ut ur strängen. Två källor är angriparnära:
// domäner ur en blocklista som HÄMTAS FRÅN EN URL, och — värre — värdnamn
// ur DHCP-leaser, som vilken enhet som helst på nätet sätter själv (DHCP
// option 12). Ovaliderad indata från nätet skrevs alltså in i
// konfigurationen för en tjänst som startas av root.
var safeDomainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// validDomain avgör om ett normaliserat domän-/värdnamn är säkert att
// skriva in i konfigurationen. Ogiltiga poster hoppas över tyst (en enda
// trasig rad i en blocklista med tiotusentals poster ska inte slå ut hela
// DNS-konfigurationen).
func validDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	return safeDomainPattern.MatchString(d)
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
// som lagras i config.Config. leases är de just nu aktiva DHCP-utlåningarna
// (från pkg/adapter/dhcp.ParseLeaseFile), använda för DHCPHostnameRegistration.
func (a *Adapter) ApplyConfig(ctx context.Context, cfg *config.Config, domains []string, leases []dhcp.Lease, dryRun bool) error {
	unit := "unbound.service"

	if cfg.DNS == nil || !cfg.DNS.Enabled {
		if dryRun {
			return nil
		}
		_ = exec.CommandContext(ctx, "systemctl", "stop", unit).Run()
		return nil
	}

	blocklistPath := filepath.Join(a.dir, blocklistFilename)
	hostsPath := filepath.Join(a.dir, hostsFilename)
	serverConf, err := GenerateServerConfig(cfg, blocklistPath, hostsPath)
	if err != nil {
		return fmt.Errorf("misslyckades generera Unbound-konfiguration: %w", err)
	}

	if dryRun {
		return nil
	}

	if err := os.MkdirAll(a.dir, 0755); err != nil {
		return fmt.Errorf("misslyckades skapa katalog %s: %w", a.dir, err)
	}
	// changed ackumulerar om NÅGON av konfigurationsfilerna faktiskt ändrades.
	// Unbound startas om bara då (eller om den inte redan kör): en omstart tar
	// DNS ur drift i flera sekunder medan blocklistan läses in på nytt, och
	// för klienterna på LAN:et ser det ut som att internet försvinner. Vid en
	// agentuppdatering är konfigurationen typiskt identisk — då ska DNS inte
	// gå ner alls (rapporterat 2026-08-26).
	changed := false

	serverChanged, err := svc.WriteIfChanged(filepath.Join(a.dir, "security-harbor.conf"), []byte(serverConf))
	if err != nil {
		return fmt.Errorf("misslyckades skriva security-harbor.conf: %w", err)
	}
	changed = changed || serverChanged

	if hasAnyBlocklistSource(cfg.DNS) {
		blocklistConf := GenerateBlocklistConfig(domains, cfg)
		blocklistChanged, err := svc.WriteIfChanged(blocklistPath, []byte(blocklistConf))
		if err != nil {
			return fmt.Errorf("misslyckades skriva %s: %w", blocklistFilename, err)
		}
		changed = changed || blocklistChanged
	}
	if cfg.DNS.DHCPHostnameRegistration || len(cfg.DNS.StaticRecords) > 0 {
		hostsConf := GenerateHostsConfig(leases, cfg)
		hostsChanged, err := svc.WriteIfChanged(hostsPath, []byte(hostsConf))
		if err != nil {
			return fmt.Errorf("misslyckades skriva %s: %w", hostsFilename, err)
		}
		changed = changed || hostsChanged
	}

	restarted, err := svc.RestartIfNeeded(ctx, unit, changed)
	if err != nil {
		return err
	}
	if !restarted {
		log.Printf("[DNS] konfigurationen oförändrad - hoppar över omstart av %s", unit)
	}

	return nil
}
