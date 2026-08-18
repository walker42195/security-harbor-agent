package dns

import (
	"strings"
	"testing"

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

	conf, err := GenerateServerConfig(cfg, "/etc/unbound/unbound.conf.d/blocklist.conf")
	if err != nil {
		t.Fatalf("GenerateServerConfig misslyckades: %v", err)
	}
	if !strings.Contains(conf, "forward-tls-upstream: yes") {
		t.Errorf("förväntade DoT aktiverat, men saknas: %s", conf)
	}
	if !strings.Contains(conf, "1.1.1.1@853#cloudflare-dns.com") {
		t.Errorf("förväntade DoT-formaterad forward-addr, men saknas: %s", conf)
	}
	if !strings.Contains(conf, "access-control: 10.0.0.0/24 allow") {
		t.Errorf("förväntade access-control för LAN-nätet, men saknas: %s", conf)
	}
}

func TestGenerateServerConfigPlainDNS(t *testing.T) {
	cfg := &config.Config{
		DNS: &config.DNSConfig{Enabled: true, UpstreamServers: []string{"9.9.9.9"}, DoTEnabled: false},
	}
	conf, err := GenerateServerConfig(cfg, "")
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
