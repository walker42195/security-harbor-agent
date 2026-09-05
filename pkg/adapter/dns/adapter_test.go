package dns

import (
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/adapter/dhcp"
	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func TestGenerateServerConfigDoT(t *testing.T) {
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, IPv4: "10.0.0.163/24"},
		},
		DNS: &config.DNSConfig{
			Enabled:         true,
			UpstreamServers: []string{"1.1.1.1", "1.0.0.1"},
			DoTEnabled:      true,
			DoTHostname:     "cloudflare-dns.com",
		},
	}

	conf, err := GenerateServerConfig(cfg, "/etc/unbound/unbound.conf.d/blocklist.conf", "")
	if err != nil {
		t.Fatalf("GenerateServerConfig misslyckades: %v", err)
	}
	if !strings.Contains(conf, "forward-tls-upstream: yes") {
		t.Errorf("förväntade DoT aktiverat, men saknas: %s", conf)
	}
	if !strings.Contains(conf, "1.1.1.1@853#cloudflare-dns.com") {
		t.Errorf("förväntade DoT-formaterad forward-addr, men saknas: %s", conf)
	}
	if !strings.Contains(conf, `tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"`) {
		t.Errorf("förväntade tls-cert-bundle när DoT är aktiverat (utan den avvisas ALLA upstream-cert, se skarp testning 2026-08-18), men saknas: %s", conf)
	}
	if !strings.Contains(conf, "access-control: 10.0.0.0/24 allow") {
		t.Errorf("förväntade access-control för LAN-nätet, men saknas: %s", conf)
	}
}

// TestGenerateServerConfigRecursiveSkipsForwardZone skyddar det nya
// rekursiva läget: när Recursive är satt ska INGEN forward-zone skrivas
// alls, även om UpstreamServers råkar vara ifyllda (t.ex. kvarlämnat från
// ett tidigare läge) — annars slår Unbound av misstag mot upstreams ändå.
func TestGenerateServerConfigRecursiveSkipsForwardZone(t *testing.T) {
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, IPv4: "10.0.0.163/24"},
		},
		DNS: &config.DNSConfig{
			Enabled:         true,
			Recursive:       true,
			UpstreamServers: []string{"1.1.1.1"},
		},
	}

	conf, err := GenerateServerConfig(cfg, "", "")
	if err != nil {
		t.Fatalf("GenerateServerConfig misslyckades: %v", err)
	}
	if strings.Contains(conf, "forward-zone:") {
		t.Errorf("förväntade INGEN forward-zone i rekursivt läge, men fick: %s", conf)
	}
}

func TestGenerateHostsConfigStaticRecords(t *testing.T) {
	cfg := &config.Config{
		DNS: &config.DNSConfig{
			Enabled:     true,
			LocalDomain: "lan",
			StaticRecords: []config.DNSStaticRecord{
				// Kortnamn: används EXAKT som angivet — inget "lan"-suffix
				// hängs på en manuell post.
				{Hostname: "server1", IP: "10.0.0.50"},
				// FQDN mot en helt annan domän ska också stå kvar orörd.
				{Hostname: "nx4.novabase.se", IP: "10.7.7.7"},
			},
		},
	}

	conf := GenerateHostsConfig(nil, cfg)
	if !strings.Contains(conf, `local-data: "server1. IN A 10.0.0.50"`) {
		t.Errorf("förväntade verbatim A-post för server1 (utan suffix), men saknas: %s", conf)
	}
	if strings.Contains(conf, "server1.lan") {
		t.Errorf("manuell post ska INTE få lokalt suffix, men fick server1.lan: %s", conf)
	}
	if !strings.Contains(conf, `local-data: "nx4.novabase.se. IN A 10.7.7.7"`) {
		t.Errorf("förväntade FQDN nx4.novabase.se orörd, men saknas: %s", conf)
	}
	if strings.Contains(conf, "novabase.se.lan") {
		t.Errorf("FQDN ska INTE få lokalt suffix påhängt: %s", conf)
	}
}

// TestGenerateHostsConfigDHCPRegistrationAndStaticOverride verifierar att
// DHCP-tilldelade värdnamn registreras när DHCPHostnameRegistration är på,
// och att en manuell StaticRecord för SAMMA värdnamn skrivs efteråt (vinner
// i Unbound, som använder den senaste local-data-definitionen).
func TestGenerateHostsConfigDHCPRegistrationAndStaticOverride(t *testing.T) {
	cfg := &config.Config{
		DNS: &config.DNSConfig{
			Enabled:                  true,
			LocalDomain:              "lan",
			DHCPHostnameRegistration: true,
			StaticRecords: []config.DNSStaticRecord{
				{Hostname: "laptop", IP: "10.0.0.99"},
			},
		},
	}
	leases := []dhcp.Lease{
		{IP: "10.0.0.42", Hostname: "laptop"},
		{IP: "10.0.0.43", Hostname: "phone"},
	}

	conf := GenerateHostsConfig(leases, cfg)
	if !strings.Contains(conf, `local-data: "phone.lan. IN A 10.0.0.43"`) {
		t.Errorf("förväntade DHCP-registrerad post för phone.lan, men saknas: %s", conf)
	}
	dhcpIdx := strings.Index(conf, "10.0.0.42")
	staticIdx := strings.Index(conf, "10.0.0.99")
	if dhcpIdx == -1 || staticIdx == -1 || staticIdx < dhcpIdx {
		t.Errorf("förväntade att den manuella posten för laptop.lan (10.0.0.99) skrivs EFTER DHCP-posten (10.0.0.42) så den vinner: %s", conf)
	}
}

// TestGenerateServerConfigBindsOnlyLANIPsNotWildcard skyddar mot en
// regression upptäckt vid skarp testning mot 10.0.0.163 2026-08-18:
// `interface: 0.0.0.0` kolliderar med systemd-resolved (Ubuntu/Debian),
// som redan äger loopback-DNS-stubben (127.0.0.53/.54:53) — Unbound
// vägrade starta med "Address already in use for 0.0.0.0 port 53". Ska
// bara binda till LAN-interfacens specifika IP:er.
func TestGenerateServerConfigBindsOnlyLANIPsNotWildcard(t *testing.T) {
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{ID: "wan0", Device: "ens18", Zone: "WAN", Enabled: true, IPv4: "203.0.113.1/24"},
			{ID: "lan0", Device: "ens19", Zone: "LAN", Enabled: true, IPv4: "10.0.0.163/24"},
			{ID: "vlan10", Device: "ens19.10", Zone: "SERVERS", Enabled: true, IPv4: "192.168.10.1/24"},
		},
		DNS: &config.DNSConfig{Enabled: true, UpstreamServers: []string{"1.1.1.1"}},
	}
	conf, err := GenerateServerConfig(cfg, "", "")
	if err != nil {
		t.Fatalf("GenerateServerConfig misslyckades: %v", err)
	}
	if strings.Contains(conf, "interface: 0.0.0.0") {
		t.Errorf("ska inte binda till 0.0.0.0 (wildcard) — kolliderar med systemd-resolved: %s", conf)
	}
	if !strings.Contains(conf, "interface: 10.0.0.163") {
		t.Errorf("förväntade en interface-rad för LAN-IP:n 10.0.0.163: %s", conf)
	}
	if strings.Contains(conf, "203.0.113.1") {
		t.Errorf("ska inte binda till WAN-IP:n: %s", conf)
	}
}

func TestGenerateServerConfigPlainDNS(t *testing.T) {
	cfg := &config.Config{
		DNS: &config.DNSConfig{Enabled: true, UpstreamServers: []string{"9.9.9.9"}, DoTEnabled: false},
	}
	conf, err := GenerateServerConfig(cfg, "", "")
	if err != nil {
		t.Fatalf("GenerateServerConfig misslyckades: %v", err)
	}
	if strings.Contains(conf, "forward-tls-upstream") {
		t.Errorf("DoT ska inte vara med när DoTEnabled=false: %s", conf)
	}
	if !strings.Contains(conf, "forward-addr: 9.9.9.9\n") {
		t.Errorf("förväntade en vanlig (icke-DoT) forward-addr, men saknas: %s", conf)
	}
}

// TestGenerateBlocklistConfigHasServerHeader skyddar mot en regression
// upptäckt vid skarp testning mot 10.0.0.163 2026-08-18: `local-zone:` är
// en server:-klausul-option. Utan ett eget `server:`-huvud i den
// inkluderade filen avvisade Unbound hela konfigurationen med "syntax
// error, is there no section start after an include-toplevel directive
// perhaps" och startade aldrig.
func TestGenerateBlocklistConfigHasServerHeader(t *testing.T) {
	cfg := &config.Config{DNS: &config.DNSConfig{Enabled: true}}
	conf := GenerateBlocklistConfig([]string{"malware.example.com"}, cfg)
	if !strings.HasPrefix(strings.TrimSpace(conf), "server:") {
		t.Fatalf("blocklist.conf måste börja med ett server:-huvud, fick: %q", conf)
	}
}

func TestGenerateBlocklistConfigAllowlistOverride(t *testing.T) {
	cfg := &config.Config{
		DNS: &config.DNSConfig{
			Enabled:              true,
			CustomBlockedDomains: []string{"manually-blocked.example"},
			CustomAllowedDomains: []string{"malware.example.com"},
		},
	}
	conf := GenerateBlocklistConfig([]string{"malware.example.com", "tracker.example.net"}, cfg)

	if !strings.Contains(conf, `local-zone: "tracker.example.net." always_nxdomain`) {
		t.Errorf("förväntade tracker.example.net blockerad: %s", conf)
	}
	if !strings.Contains(conf, `local-zone: "manually-blocked.example." always_nxdomain`) {
		t.Errorf("förväntade en manuellt tillagd blockerad domän: %s", conf)
	}
	if strings.Contains(conf, `"malware.example.com." always_nxdomain`) {
		t.Errorf("malware.example.com finns på allowlistan och ska INTE blockeras: %s", conf)
	}
	if !strings.Contains(conf, `local-zone: "malware.example.com." transparent`) {
		t.Errorf("förväntade en transparent (allowlist-)post för malware.example.com: %s", conf)
	}
}

// TestDNSFloodProtection verifierar att flod-/svältningsskyddet (ip-ratelimit
// per käll-IP + ratelimit + buffertar) renderas, med säker default när inget
// angetts, och att -1 stänger av per-IP-taket.
func TestDNSFloodProtection(t *testing.T) {
	base := func(rl int) *config.Config {
		return &config.Config{
			Interfaces: []config.Interface{{Device: "ens19", Enabled: true, Zone: "LAN", IPv4: "10.5.5.1/24"}},
			DNS:        &config.DNSConfig{Enabled: true, UpstreamServers: []string{"1.1.1.1"}, QueryRateLimitPerIP: rl},
		}
	}
	// Default (0 → 200)
	out, err := GenerateServerConfig(base(0), "", "")
	if err != nil {
		t.Fatalf("fel: %v", err)
	}
	for _, want := range []string{"ip-ratelimit: 200", "ratelimit: 1000", "so-rcvbuf: 4m", "jostle-timeout: 200"} {
		if !strings.Contains(out, want) {
			t.Errorf("saknar %q i:\n%s", want, out)
		}
	}
	// Explicit värde
	out2, _ := GenerateServerConfig(base(500), "", "")
	if !strings.Contains(out2, "ip-ratelimit: 500") || !strings.Contains(out2, "ratelimit: 2500") {
		t.Errorf("förväntade ip-ratelimit: 500 / ratelimit: 2500, fick:\n%s", out2)
	}
	// -1 stänger av per-IP-taket (men buffertarna ska finnas kvar)
	out3, _ := GenerateServerConfig(base(-1), "", "")
	if strings.Contains(out3, "ip-ratelimit:") {
		t.Errorf("ip-ratelimit skulle vara avstängt vid -1, fick:\n%s", out3)
	}
	if !strings.Contains(out3, "so-rcvbuf: 4m") {
		t.Errorf("buffertar ska finnas även med per-IP-tak av, fick:\n%s", out3)
	}
}
