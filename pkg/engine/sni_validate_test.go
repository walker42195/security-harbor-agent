package engine

import (
	"strings"
	"testing"

	"github.com/walker42195/security-harbor-agent/pkg/config"
)

func baseCfgWithSNI(routes []config.SNIRoute) *config.Config {
	return &config.Config{
		Settings:  config.Settings{APIPort: 8443},
		SNIRoutes: routes,
	}
}

func wantErr(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil {
		t.Fatalf("förväntade ett fel som innehåller %q, fick nil", sub)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("förväntade fel med %q, fick: %v", sub, err)
	}
}

func TestValidateSNIRoutesOK(t *testing.T) {
	cfg := baseCfgWithSNI([]config.SNIRoute{
		{ID: "r1", Enabled: true, ListenPort: 443, Backends: []config.SNIBackend{
			{Hostnames: []string{"a.se"}, TargetIP: "10.0.0.24", TargetPort: 8006},
			{Hostnames: []string{"b.se"}, TargetIP: "10.0.0.25", TargetPort: 8006},
		}},
	})
	if err := validateSNIRoutes(cfg); err != nil {
		t.Fatalf("giltig rutt underkändes: %v", err)
	}
}

func TestValidateSNIRoutesDuplicateHostname(t *testing.T) {
	cfg := baseCfgWithSNI([]config.SNIRoute{
		{ID: "r1", Enabled: true, ListenPort: 443, Backends: []config.SNIBackend{
			{Hostnames: []string{"a.se"}, TargetIP: "10.0.0.24", TargetPort: 8006},
			{Hostnames: []string{"A.se"}, TargetIP: "10.0.0.25", TargetPort: 8006},
		}},
	})
	wantErr(t, validateSNIRoutes(cfg), "tvetydig")
}

func TestValidateSNIRoutesDuplicatePort(t *testing.T) {
	cfg := baseCfgWithSNI([]config.SNIRoute{
		{ID: "r1", Enabled: true, ListenPort: 443, Backends: []config.SNIBackend{{Hostnames: []string{"a.se"}, TargetIP: "10.0.0.24", TargetPort: 8006}}},
		{ID: "r2", Enabled: true, ListenPort: 443, Backends: []config.SNIBackend{{Hostnames: []string{"b.se"}, TargetIP: "10.0.0.25", TargetPort: 8006}}},
	})
	wantErr(t, validateSNIRoutes(cfg), "används redan")
}

func TestValidateSNIRoutesPortEqualsAPI(t *testing.T) {
	cfg := baseCfgWithSNI([]config.SNIRoute{
		{ID: "r1", Enabled: true, ListenPort: 8443, Backends: []config.SNIBackend{{Hostnames: []string{"a.se"}, TargetIP: "10.0.0.24", TargetPort: 8006}}},
	})
	wantErr(t, validateSNIRoutes(cfg), "administrations-API")
}

func TestValidateSNIRoutesPortEqualsDNAT(t *testing.T) {
	cfg := baseCfgWithSNI([]config.SNIRoute{
		{ID: "r1", Enabled: true, ListenPort: 443, Backends: []config.SNIBackend{{Hostnames: []string{"a.se"}, TargetIP: "10.0.0.24", TargetPort: 8006}}},
	})
	cfg.Policies = []config.Policy{
		{ID: "p1", Enabled: true, Action: config.ActionDNAT, NAT: &config.NATConfig{ExternalPort: 443, InternalIP: "10.0.0.9", InternalPort: 443}},
	}
	wantErr(t, validateSNIRoutes(cfg), "krockar med en port forward")
}

func TestValidateSNIRoutesBackendNoTarget(t *testing.T) {
	cfg := baseCfgWithSNI([]config.SNIRoute{
		{ID: "r1", Enabled: true, ListenPort: 443, Backends: []config.SNIBackend{{Hostnames: []string{"a.se"}}}},
	})
	wantErr(t, validateSNIRoutes(cfg), "saknar mål")
}

func TestValidateSNIRoutesBackendBothTargets(t *testing.T) {
	cfg := baseCfgWithSNI([]config.SNIRoute{
		{ID: "r1", Enabled: true, ListenPort: 443, Backends: []config.SNIBackend{
			{Hostnames: []string{"a.se"}, TargetIP: "10.0.0.24", TargetPort: 8006, LocalService: config.LocalServiceOpenVPN},
		}},
	})
	wantErr(t, validateSNIRoutes(cfg), "både")
}

func TestValidateSNIRoutesOpenVPNRequiresTCP(t *testing.T) {
	cfg := baseCfgWithSNI([]config.SNIRoute{
		{ID: "r1", Enabled: true, ListenPort: 443,
			Backends:       []config.SNIBackend{{Hostnames: []string{"a.se"}, TargetIP: "10.0.0.24", TargetPort: 8006}},
			DefaultBackend: &config.SNIBackend{LocalService: config.LocalServiceOpenVPN}},
	})
	cfg.OpenVPN = &config.OpenVPNConfig{Enabled: true, Protocol: "udp"}
	wantErr(t, validateSNIRoutes(cfg), "TCP-läge")

	cfg.OpenVPN.Protocol = "tcp"
	if err := validateSNIRoutes(cfg); err != nil {
		t.Fatalf("OpenVPN tcp-fallback borde godkännas: %v", err)
	}
}

func TestValidateSNIRoutesOpenVPNMustBeEnabled(t *testing.T) {
	cfg := baseCfgWithSNI([]config.SNIRoute{
		{ID: "r1", Enabled: true, ListenPort: 443,
			DefaultBackend: &config.SNIBackend{LocalService: config.LocalServiceOpenVPN}},
	})
	wantErr(t, validateSNIRoutes(cfg), "inte aktiverat")
}
