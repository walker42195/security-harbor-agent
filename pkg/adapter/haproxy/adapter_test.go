package haproxy

import (
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func TestGenerateConfigInternalBackends(t *testing.T) {
	cfg := &config.Config{
		SNIRoutes: []config.SNIRoute{
			{
				ID: "r1", Name: "Webb", Enabled: true, ListenPort: 443,
				Backends: []config.SNIBackend{
					{Hostnames: []string{"app1.exempel.se"}, TargetIP: "192.168.20.10", TargetPort: 443},
					{Hostnames: []string{"app2.exempel.se"}, TargetIP: "192.168.20.11", TargetPort: 443},
				},
			},
		},
	}
	out, err := GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}
	for _, want := range []string{
		"frontend fe_r1",
		"bind :443",
		"mode tcp",
		"req.ssl_sni -i app1.exempel.se",
		"req.ssl_sni -i app2.exempel.se",
		"use_backend be_r1_0 if",
		"use_backend be_r1_1 if",
		"server s0 192.168.20.10:443",
		"server s0 192.168.20.11:443",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("förväntade %q i genererad config:\n%s", want, out)
		}
	}
	// Ingen default_backend när DefaultBackend saknas.
	if strings.Contains(out, "default_backend") {
		t.Errorf("oväntad default_backend utan DefaultBackend:\n%s", out)
	}
}

func TestGenerateConfigWildcard(t *testing.T) {
	cfg := &config.Config{
		SNIRoutes: []config.SNIRoute{
			{
				ID: "r1", Enabled: true, ListenPort: 443,
				Backends: []config.SNIBackend{
					{Hostnames: []string{"*.kund.exempel.se"}, TargetIP: "10.0.0.50", TargetPort: 8443},
				},
			},
		},
	}
	out, err := GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}
	if !strings.Contains(out, "req.ssl_sni -m end -i .kund.exempel.se") {
		t.Errorf("wildcard ska bli suffix-match (-m end -i .kund.exempel.se):\n%s", out)
	}
}

func TestGenerateConfigOpenVPNFallback(t *testing.T) {
	cfg := &config.Config{
		OpenVPN: &config.OpenVPNConfig{Enabled: true, Protocol: "tcp", ListenPort: 443},
		SNIRoutes: []config.SNIRoute{
			{
				ID: "r1", Enabled: true, ListenPort: 443,
				Backends: []config.SNIBackend{
					{Hostnames: []string{"app.exempel.se"}, TargetIP: "192.168.20.10", TargetPort: 443},
				},
				DefaultBackend: &config.SNIBackend{LocalService: config.LocalServiceOpenVPN},
			},
		},
	}
	out, err := GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}
	if !strings.Contains(out, "default_backend be_r1_default") {
		t.Errorf("saknar default_backend för fallback:\n%s", out)
	}
	if !strings.Contains(out, "server ovpn 127.0.0.1:11194") {
		t.Errorf("OpenVPN-fallback ska peka på loopback 11194:\n%s", out)
	}
}

func TestGenerateConfigNoActiveRoutes(t *testing.T) {
	cfg := &config.Config{
		SNIRoutes: []config.SNIRoute{
			{ID: "r1", Enabled: false, ListenPort: 443, Backends: []config.SNIBackend{{Hostnames: []string{"x"}, TargetIP: "1.1.1.1", TargetPort: 443}}},
		},
	}
	out, err := GenerateConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}
	if strings.Contains(out, "frontend") {
		t.Errorf("inaktiva rutter ska inte generera en frontend:\n%s", out)
	}
	if hasActiveRoutes(cfg) {
		t.Errorf("hasActiveRoutes ska vara false när enda rutten är inaktiv")
	}
}
